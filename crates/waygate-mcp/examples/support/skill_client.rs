//! Client-side retention example. The transport still checks current access.

use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};

pub struct Workflow {
    uri: String,
    revision: String,
    document_hash: String,
    complete: Option<Value>,
}

impl Workflow {
    pub fn from_complete(response: Value) -> Result<Self> {
        ensure!(
            response["instructions"].is_string() && response["files"].is_array(),
            "complete workflow response required"
        );
        let uri = response["skill"]["uri"]
            .as_str()
            .context("missing skill URI")?
            .to_owned();
        let revision = response["skill"]["revision"]
            .as_str()
            .context("missing revision")?
            .to_owned();
        let document_hash = response["document_hash"]
            .as_str()
            .context("missing document hash")?
            .to_owned();
        Ok(Self {
            uri,
            revision,
            document_hash,
            complete: Some(response),
        })
    }

    pub fn load_arguments(&self) -> Value {
        let mut arguments = json!({"uri":self.uri,"revision":self.revision});
        if self.complete.is_some() {
            arguments["known_document_hash"] = json!(self.document_hash);
        }
        arguments
    }

    pub fn accept(&mut self, response: Value) -> Result<&Value> {
        if response["unchanged"] == true {
            ensure!(
                self.complete.is_some(),
                "unchanged response cannot replace missing instructions"
            );
            ensure!(
                response["uri"] == self.uri
                    && response["revision"] == self.revision
                    && response["document_hash"] == self.document_hash,
                "unchanged response does not match retained workflow"
            );
        } else {
            let replacement = Self::from_complete(response)?;
            ensure!(
                replacement.uri == self.uri && replacement.revision == self.revision,
                "pinned workflow changed; explicitly rediscover and reassess"
            );
            *self = replacement;
        }
        self.complete()
    }

    pub fn complete(&self) -> Result<&Value> {
        self.complete
            .as_ref()
            .context("workflow instructions must be loaded again")
    }

    pub fn forget_content(&mut self) {
        self.complete = None;
    }

    pub fn file_arguments(&self, path: &str) -> Result<Value> {
        let files = self.complete()?["files"]
            .as_array()
            .context("missing inventory")?;
        let Some(file) = files.iter().find(|file| file["path"] == path) else {
            bail!("requested file is absent from the retained inventory");
        };
        let uri = file["uri"].as_str().context("missing file URI")?;
        Ok(json!({"uri":uri,"revision":self.revision}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> Value {
        json!({"skill":{"uri":"skill://fixture/demo/SKILL.md","revision":"revision-A"},"instructions":"Read references/check.md","files":[{"uri":"skill://fixture/demo/references/check.md","path":"references/check.md"}],"document_hash":"retained-hash"})
    }

    fn unchanged() -> Value {
        json!({"unchanged":true,"uri":"skill://fixture/demo/SKILL.md","revision":"revision-A","document_hash":"retained-hash"})
    }

    #[test]
    fn retained_content_supports_recheck_and_selective_file_read() {
        let mut workflow = Workflow::from_complete(complete()).unwrap();
        assert_eq!(
            workflow.load_arguments()["known_document_hash"],
            "retained-hash"
        );
        assert_eq!(workflow.accept(unchanged()).unwrap(), &complete());
        assert_eq!(
            workflow.file_arguments("references/check.md").unwrap(),
            json!({"uri":"skill://fixture/demo/references/check.md","revision":"revision-A"})
        );
        assert!(workflow.file_arguments("../other.md").is_err());
    }

    #[test]
    fn hash_alone_never_skips_lost_instructions() {
        let mut workflow = Workflow::from_complete(complete()).unwrap();
        workflow.forget_content();
        assert!(workflow
            .load_arguments()
            .get("known_document_hash")
            .is_none());
        assert!(workflow.accept(unchanged()).is_err());
        assert!(workflow.file_arguments("references/check.md").is_err());
        assert_eq!(workflow.accept(complete()).unwrap(), &complete());
    }

    #[test]
    fn changed_revision_or_hash_requires_correct_identity() {
        let mut workflow = Workflow::from_complete(complete()).unwrap();
        let mut changed = unchanged();
        changed["document_hash"] = json!("different-hash");
        assert!(workflow.accept(changed).is_err());
        let mut changed = complete();
        changed["skill"]["revision"] = json!("revision-B");
        assert!(workflow.accept(changed.clone()).is_err());
        assert_eq!(
            Workflow::from_complete(changed).unwrap().load_arguments()["revision"],
            "revision-B"
        );
    }
}
