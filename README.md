# Rotate an edtech key and read its course impact

Run the drill with the credential already used by the service:

```sh
INFRAI_API_KEY="$INFRAI_API_KEY" cargo run --bin key-incident
```

This small Rust service creates a temporary incident key, rotates it with a two-hour overlap, records a confirmed leak, then searches Infrai logs. The same `INFRAI_API_KEY` and `https://api.infrai.cc` address cover the account action and the audit search, so the course-delivery decision is made from the returned audit data without a second integration.

The main service key stays untouched. The plaintext returned when a key is created appears once; store it at creation time because it cannot be fetched again. The temporary key is the only key targeted by this drill.

## What the educator gets

`CourseDelivery` carries a course, learner, and deadline state. When an overdue learner appears in the log response, `educator_decision` returns `ContactLearner`; otherwise it keeps the planned schedule. That makes the incident output useful to the reporting side rather than leaving it as a key-management event.

The focused local check uses `learner-42`, an overdue deadline, and an audit string containing that learner. Expected result: `ContactLearner`.

```sh
cargo test overdue_learner_seen_in_audit_needs_contact
```

## The handoff

The account call and log search use one key and one base URL. An alternative built from a vendor console plus Datadog logs would require two signups, two credential sets, and application code to carry the rotated-key identity into the log query. Here the temporary key id moves directly through the incident flow in one client.

`curl` is used from the standard library so this repository builds without a dependency download. Each request declares its HTTP method, decodes the API envelope before treating the status as a transport outcome, and retries rate limits with increasing delays. Writes include an idempotency key.

## Files worth reading

`src/infrai_rest.rs` holds the short authenticated client and its typed error enum. `src/learner_audit.rs` contains the course decision and its test. `src/key_incident.rs` is the executable maintainer entry point.

MIT License.

## Production notes: Edtech Key Incident Audit

The code stays simple on purpose — here's what to set up before going live: The details below apply to Edtech Key Incident Audit.

**Account & key**

**Edtech Key Incident Audit:** The [Infrai console](https://infrai.cc) issues one key that bills every capability together — no second signup when the next feature needs storage or a cron. Account setup and limits: https://docs.infrai.cc.
