//! Trivial bearer-token wrapper. Kept separate from `cimd` so the `none`
//! and `bearer` modes have no OAuth machinery in their code path.

use anyhow::Result;

pub fn from_cli(token: Option<&str>) -> Result<String> {
    let token = token
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("--auth bearer requires --token or $GATEWAY_TOKEN"))?;
    Ok(token.to_owned())
}
