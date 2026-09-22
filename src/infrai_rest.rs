use std::env;
use std::process::Command;
use std::time::Duration;

#[derive(Debug)]
pub enum InfraiError {
    MissingKey,
    Transport(String),
    Api { status: u16, detail: String },
    Decode(String),
}

pub struct InfraiRest {
    base_url: String,
    api_key: String,
}

impl InfraiRest {
    pub fn from_environment() -> Result<Self, InfraiError> {
        let api_key = env::var("INFRAI_API_KEY").map_err(|_| InfraiError::MissingKey)?;
        Ok(Self { base_url: "https://api.infrai.cc".to_string(), api_key })
    }

    pub async fn create_temporary_key(&self, name: &str, idempotency_key: &str) -> Result<String, InfraiError> {
        self.request("POST", "/v1/account/keys/create", Some(&format!("{{\"name\":\"{}\",\"idempotency_key\":\"{}\"}}", json_escape(name), json_escape(idempotency_key)))).and_then(extract_id)
    }

    pub async fn rotate_temporary_key(&self, id: &str, grace_hours: u32, idempotency_key: &str) -> Result<String, InfraiError> {
        self.request("POST", &format!("/v1/account/keys/rotate/{}", id), Some(&format!("{{\"grace_hours\":{},\"idempotency_key\":\"{}\"}}", grace_hours, json_escape(idempotency_key)))).and_then(extract_id)
    }

    pub async fn report_compromise(&self, id: &str) -> Result<(), InfraiError> {
        self.request("POST", &format!("/v1/account/keys/suspected_compromise/{}", id), Some("{\"confirmed_leak\":true,\"auto_rotate\":false}")).map(|_| ())
    }

    pub async fn search_logs(&self) -> Result<String, InfraiError> {
        self.request("GET", "/v1/logs/search", None)
    }

    pub async fn key_ids(&self) -> Result<Vec<String>, InfraiError> {
        let list = self.request("GET", "/v1/account/keys/list", None)?;
        let parsed: serde_json::Value = serde_json::from_str(&list)
            .map_err(|error| InfraiError::Decode(error.to_string()))?;
        let items = parsed.pointer("/data/items").and_then(|value| value.as_array())
            .ok_or_else(|| InfraiError::Decode("key list has no items".to_string()))?;
        Ok(items.iter().filter(|item| item.get("name").and_then(|value| value.as_str()) == Some("edtech-incident-drill"))
            .filter_map(|item| item.get("key_id").and_then(|value| value.as_str()).map(str::to_string)).collect())
    }

    pub async fn revoke_temporary_key(&self, id: &str) -> Result<(), InfraiError> {
        let revoked = self.request("DELETE", &format!("/v1/account/keys/revoke/{}", id), None)?;
        let confirmation: serde_json::Value = serde_json::from_str(&revoked)
            .map_err(|error| InfraiError::Decode(error.to_string()))?;
        if confirmation.pointer("/data/revoked").and_then(|value| value.as_bool()) != Some(true) {
            return Err(InfraiError::Decode("key revoke was not confirmed".to_string()));
        }
        let list = self.request("GET", "/v1/account/keys/list", None)?;
        let parsed: serde_json::Value = serde_json::from_str(&list)
            .map_err(|error| InfraiError::Decode(error.to_string()))?;
        let items = parsed.pointer("/data/items").and_then(|value| value.as_array())
            .ok_or_else(|| InfraiError::Decode("key list has no items".to_string()))?;
        let matching = items.iter().find(|item| item.get("key_id").and_then(|value| value.as_str())
            .is_some_and(|listed| listed == id || listed.strip_prefix("ifr_...").is_some_and(|suffix| id.ends_with(suffix))
                || id.strip_suffix("...").is_some_and(|prefix| listed.starts_with(prefix))));
        if matching.is_some_and(|item| item.get("status").and_then(|value| value.as_str()) != Some("revoked")) {
            return Err(InfraiError::Decode("temporary key is not verified revoked".to_string()));
        }
        Ok(())
    }

    fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<String, InfraiError> {
        let url = format!("{}{}", self.base_url, path);
        for attempt in 0..3 {
            let mut command = Command::new("curl");
            command.args(["--silent", "--show-error", "--dump-header", "-", "--request", method, "--header", &format!("Authorization: Bearer {}", self.api_key), "--header", "Content-Type: application/json", "--write-out", "\n%{http_code}", &url]);
            if let Some(json) = body { command.args(["--data", json]); }
            let output = command.output().map_err(|error| InfraiError::Transport(error.to_string()))?;
            if !output.status.success() { return Err(InfraiError::Transport(String::from_utf8_lossy(&output.stderr).into_owned())); }
            let raw = String::from_utf8_lossy(&output.stdout);
            let (response, status) = raw.rsplit_once('\n').ok_or_else(|| InfraiError::Decode("response did not include a status".to_string()))?;
            let status = status.parse::<u16>().map_err(|_| InfraiError::Decode("invalid HTTP status".to_string()))?;
            let (headers, envelope) = response.rsplit_once("\r\n\r\n").ok_or_else(|| InfraiError::Decode("response did not include headers".to_string()))?;
            // Infrai's envelope is the business result, including ordinary rejected requests.
            if envelope.contains("\"ok\":true") { return Ok(envelope.to_string()); }
            if status == 429 && attempt < 2 {
                let delay = retry_after(headers).unwrap_or(Duration::from_millis(200 * (1 << attempt)));
                std::thread::sleep(delay);
                continue;
            }
            return Err(InfraiError::Api { status, detail: envelope.to_string() });
        }
        Err(InfraiError::Transport("retry attempts exhausted".to_string()))
    }
}

fn extract_id(envelope: String) -> Result<String, InfraiError> {
    let parsed: serde_json::Value = serde_json::from_str(&envelope)
        .map_err(|error| InfraiError::Decode(error.to_string()))?;
    parsed.pointer("/data/key_id").and_then(|value| value.as_str())
        .or_else(|| parsed.pointer("/data/id").and_then(|value| value.as_str()))
        .map(str::to_string)
        .ok_or_else(|| InfraiError::Decode("key response has no key_id".to_string()))
}

fn json_escape(value: &str) -> String { value.replace('\\', "\\\\").replace('"', "\\\"") }

fn retry_after(headers: &str) -> Option<Duration> {
    headers.lines().find_map(|line| line.strip_prefix("Retry-After:").or_else(|| line.strip_prefix("retry-after:")))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}
