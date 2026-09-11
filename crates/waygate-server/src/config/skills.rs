use anyhow::{Context, Result};

use crate::skills_git::{SkillsGitConfig, DEFAULT_GIT_SNAPSHOT_TIMEOUT};

const COMPANION_VARS: &[&str] = &[
    "GATEWAY_SKILLS_GIT_REPOSITORY",
    "GATEWAY_SKILLS_GIT_REF",
    "GATEWAY_SKILLS_GIT_EXPECTED_COMMIT",
    "GATEWAY_SKILLS_GIT_EXPECTED_TREE",
    "GATEWAY_SKILLS_GIT_ROOTS",
    "GATEWAY_SKILLS_SOURCE_ID",
    "GATEWAY_SKILLS_GIT_TOKEN_ENV",
    "GATEWAY_SKILLS_REFRESH_INTERVAL_SECONDS",
];

pub(super) fn from_env() -> Result<Option<SkillsGitConfig>> {
    let api_url = match waygate_core::env::optional("GATEWAY_SKILLS_GIT_API_URL") {
        Some(value) => value,
        None => {
            if let Some(name) = COMPANION_VARS
                .iter()
                .find(|name| waygate_core::env::optional(name).is_some())
            {
                anyhow::bail!(
                    "{name} is set but GATEWAY_SKILLS_GIT_API_URL is absent; set the Git API URL or remove the unused skill source setting"
                );
            }
            return Ok(None);
        }
    };
    let repository = waygate_core::env::optional("GATEWAY_SKILLS_GIT_REPOSITORY")
        .context("GATEWAY_SKILLS_GIT_API_URL requires GATEWAY_SKILLS_GIT_REPOSITORY")?;
    let roots = waygate_core::env::optional("GATEWAY_SKILLS_GIT_ROOTS")
        .context("GATEWAY_SKILLS_GIT_API_URL requires GATEWAY_SKILLS_GIT_ROOTS")?
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if roots.iter().any(String::is_empty) {
        anyhow::bail!(
            "GATEWAY_SKILLS_GIT_ROOTS must be a comma-separated list of repository paths"
        );
    }
    let token_env = waygate_core::env::optional("GATEWAY_SKILLS_GIT_TOKEN_ENV");
    if let Some(value) = &token_env {
        validate_env_identifier("GATEWAY_SKILLS_GIT_TOKEN_ENV", value)?;
    }
    let refresh_interval = waygate_core::env::duration_secs_zero_disables(
        "GATEWAY_SKILLS_REFRESH_INTERVAL_SECONDS",
        300,
        30,
        "use 0 to disable, otherwise pick at least 30s",
    )?;

    Ok(Some(SkillsGitConfig {
        api_url: url::Url::parse(&api_url)
            .context("GATEWAY_SKILLS_GIT_API_URL must be a valid URL")?,
        repository,
        reference: waygate_core::env::optional("GATEWAY_SKILLS_GIT_REF")
            .unwrap_or_else(|| "main".to_owned()),
        expected_commit: waygate_core::env::optional("GATEWAY_SKILLS_GIT_EXPECTED_COMMIT"),
        expected_tree: waygate_core::env::optional("GATEWAY_SKILLS_GIT_EXPECTED_TREE"),
        source_id: waygate_core::env::optional("GATEWAY_SKILLS_SOURCE_ID")
            .context("GATEWAY_SKILLS_GIT_API_URL requires GATEWAY_SKILLS_SOURCE_ID (the stable namespace in skill URIs)")?,
        roots,
        token_env,
        refresh_interval,
        snapshot_timeout: DEFAULT_GIT_SNAPSHOT_TIMEOUT,
    }))
}

fn validate_env_identifier(setting: &str, value: &str) -> Result<()> {
    let mut chars = value.chars();
    let valid_first = chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic());
    if !valid_first || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        anyhow::bail!(
            "{setting} must name an environment variable using ASCII letters, digits, and underscores, and must not start with a digit"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ENV_GUARD;

    struct EnvRestore(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl EnvRestore {
        fn clear(names: &'static [&'static str]) -> Self {
            let saved = names
                .iter()
                .map(|name| (*name, std::env::var_os(name)))
                .collect();
            for name in names {
                std::env::remove_var(name);
            }
            Self(saved)
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (name, value) in self.0.drain(..) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    const SKILLS_GIT_ENV: &[&str] = &[
        "GATEWAY_SKILLS_GIT_API_URL",
        "GATEWAY_SKILLS_GIT_REPOSITORY",
        "GATEWAY_SKILLS_GIT_REF",
        "GATEWAY_SKILLS_GIT_EXPECTED_COMMIT",
        "GATEWAY_SKILLS_GIT_EXPECTED_TREE",
        "GATEWAY_SKILLS_GIT_ROOTS",
        "GATEWAY_SKILLS_SOURCE_ID",
        "GATEWAY_SKILLS_GIT_TOKEN_ENV",
        "GATEWAY_SKILLS_REFRESH_INTERVAL_SECONDS",
    ];

    #[test]
    fn configuration_is_explicit_and_references_optional_token_by_name() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|error| error.into_inner());
        let _restore = EnvRestore::clear(SKILLS_GIT_ENV);

        assert!(from_env().expect("absent config").is_none());
        std::env::set_var("GATEWAY_SKILLS_GIT_REPOSITORY", "owner/skills");
        assert!(from_env().is_err());

        std::env::set_var("GATEWAY_SKILLS_GIT_API_URL", "https://git.example/api/v1");
        std::env::set_var("GATEWAY_SKILLS_GIT_ROOTS", "plugins,skills");
        let missing_source = from_env().expect_err("an enabled source needs an explicit identity");
        assert!(missing_source
            .to_string()
            .contains("GATEWAY_SKILLS_SOURCE_ID"));
        std::env::set_var("GATEWAY_SKILLS_SOURCE_ID", "team-skills");
        let anonymous = from_env().expect("config").expect("configured source");
        assert_eq!(anonymous.source_id, "team-skills");
        assert_eq!(anonymous.reference, "main");
        assert_eq!(anonymous.roots, ["plugins", "skills"]);
        assert!(anonymous.token_env.is_none());

        std::env::set_var("GATEWAY_SKILLS_GIT_TOKEN_ENV", "SKILLS_GIT_TOKEN");
        assert_eq!(
            from_env()
                .expect("token config")
                .expect("configured source")
                .token_env
                .as_deref(),
            Some("SKILLS_GIT_TOKEN")
        );
        std::env::set_var("GATEWAY_SKILLS_GIT_TOKEN_ENV", "not a variable");
        assert!(from_env().is_err());
    }
}
