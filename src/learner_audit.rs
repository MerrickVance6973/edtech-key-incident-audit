use crate::infrai_rest::{InfraiError, InfraiRest};

#[derive(Debug, Clone)]
pub struct CourseDelivery {
    pub course: String,
    pub learner: String,
    pub deadline_passed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EducatorDecision { ContactLearner, KeepScheduled }

pub fn educator_decision(delivery: &CourseDelivery, log_text: &str) -> EducatorDecision {
    if delivery.deadline_passed && log_text.contains(&delivery.learner) { EducatorDecision::ContactLearner } else { EducatorDecision::KeepScheduled }
}

pub struct KeyIncident<'a> { rest: &'a InfraiRest }

impl<'a> KeyIncident<'a> {
    pub fn new(rest: &'a InfraiRest) -> Self { Self { rest } }

    pub async fn rotate_and_audit(&self, delivery: &CourseDelivery) -> Result<EducatorDecision, InfraiError> {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| InfraiError::Transport(error.to_string()))?.as_nanos();
        let temporary_id = self.rest.create_temporary_key("edtech-incident-drill", &format!("edtech-incident-create-{nonce}")).await?;
        let before = self.rest.key_ids().await;
        let rotated = match before {
            Ok(ref existing) => {
                let rotation = self.rest.rotate_temporary_key(&temporary_id, 2, &format!("edtech-incident-rotate-{nonce}")).await;
                match rotation {
                    Ok(_) => self.rest.key_ids().await.and_then(|ids| ids.into_iter()
                        .find(|id| !existing.contains(id)).ok_or_else(|| InfraiError::Decode("rotated key missing from list".to_string()))),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        let result = async {
            let rotated_id = rotated.as_ref().map_err(|_| InfraiError::Decode("rotation failed".to_string()))?;
            self.rest.report_compromise(&temporary_id).await?;
            let logs = self.rest.search_logs().await?;
            Ok((educator_decision(delivery, &logs), rotated_id.clone()))
        }.await;
        if let Ok(ref rotated_id) = rotated {
            self.rest.revoke_temporary_key(rotated_id).await?;
        }
        self.rest.revoke_temporary_key(&temporary_id).await?;
        rotated?;
        result.map(|(decision, _)| decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overdue_learner_seen_in_audit_needs_contact() {
        let delivery = CourseDelivery { course: "algebra-1".to_string(), learner: "learner-42".to_string(), deadline_passed: true };
        assert_eq!(educator_decision(&delivery, "delivery learner-42 fetched lesson"), EducatorDecision::ContactLearner);
    }
}
