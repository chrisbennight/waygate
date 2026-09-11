//! The helper's local signing key and the RFC 9449 proofs built from it.
//!
//! The key is deliberately *not* a gateway credential. On its own it authorizes
//! nothing and names no principal. It exists so a transfer grant can be bound to
//! whoever holds it, which is what lets the opaque grant handle travel back
//! through an untrusted relay without becoming usable to anyone who reads it.
//!
//! The key is long-lived rather than per-transfer so its thumbprint can be read
//! once and reused: the thumbprint has to be known *before* the grant is
//! requested, and a fresh key per transfer would force an extra round trip
//! through that relay every time.

use std::path::Path;

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use ed25519_dalek::SigningKey;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, KeyAlgorithm,
    OctetKeyPairParameters, OctetKeyPairType, ThumbprintHash,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::TryRng as _;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// An Ed25519 key plus the JWK the gateway verifies proofs against.
pub struct HelperKey {
    jwk: Jwk,
    encoding: EncodingKey,
}

impl HelperKey {
    /// Load the key at `path`, generating one on first use.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match std::fs::File::open(path) {
            Ok(file) => Self::read_checked(file, path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Self::create_or_adopt(path, &generate_key_pem()?)
            }
            Err(e) => Err(e).with_context(|| format!("open signing key {}", path.display())),
        }
    }

    /// Judge an open key file, then read the key out of that same handle.
    ///
    /// The order and the single handle both matter. Checking a *name* and then
    /// reading it resolves the name twice, and in a directory somebody else can
    /// write, the file judged and the file read need not be the same one — a
    /// rename between the two is all it takes. A handle names one file for as
    /// long as it is held, so what is judged here is what is read.
    fn read_checked(mut file: std::fs::File, path: &Path) -> Result<Self> {
        use std::io::Read as _;

        ensure_owner_only(&file, path)?;
        let mut pem = String::new();
        file.read_to_string(&mut pem)
            .with_context(|| format!("read signing key {}", path.display()))?;
        Self::from_pem(&pem)
    }

    /// Store `pem` at `path`, or adopt whatever is already there.
    ///
    /// Split out from `load_or_create` so the losing side of a concurrent
    /// create can be exercised directly: it is otherwise reachable only by
    /// winning a race, and an untested branch here would hand back a
    /// thumbprint for a key that never reaches disk.
    fn create_or_adopt(path: &Path, pem: &str) -> Result<Self> {
        match write_private_file(path, pem.as_bytes())
            .with_context(|| format!("write signing key {}", path.display()))?
        {
            // Creation states the permissions rather than asking for them, but
            // stating is not the same as having: what a platform does with a
            // requested access list is its business, and this is the one place
            // that can still catch a mismatch before the key is used. Confirmed
            // rather than assumed, and by the same check the load path uses.
            Wrote::Created => {
                let file = std::fs::File::open(path).with_context(|| {
                    format!("reopen signing key {} to confirm it", path.display())
                })?;
                ensure_owner_only(&file, path)?;
                Self::from_pem(pem)
            }
            // Another run stored its key first. Theirs is the one on disk and
            // the one later runs will sign with, so adopt it — reporting a
            // thumbprint for a key we discarded would bind a grant to something
            // that can never redeem it.
            //
            // Adopting a key means signing with it, so it earns the same
            // scrutiny as one found by the ordinary load path. A key that
            // appeared in a directory others can write is exactly the one not
            // to trust.
            Wrote::AlreadyPresent => {
                let file = std::fs::File::open(path).with_context(|| {
                    format!(
                        "open signing key {} after a concurrent create",
                        path.display()
                    )
                })?;
                Self::read_checked(file, path)
            }
        }
    }

    fn from_pem(pem: &str) -> Result<Self> {
        let signing =
            SigningKey::from_pkcs8_pem(pem).context("signing key is not a PKCS#8 Ed25519 PEM")?;
        let encoding = EncodingKey::from_ed_pem(pem.as_bytes())
            .context("signing key rejected by JWS layer")?;
        Ok(Self {
            jwk: public_jwk(&signing),
            encoding,
        })
    }

    /// The RFC 7638 SHA-256 thumbprint the gateway binds a grant to.
    pub fn thumbprint(&self) -> String {
        self.jwk.thumbprint(ThumbprintHash::SHA256)
    }

    /// Build a proof for one request.
    ///
    /// `access_token` must be supplied for a request that carries one and
    /// omitted otherwise: the verifier rejects a proof whose `ath` presence
    /// disagrees with the request.
    pub fn proof(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<String> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("dpop+jwt".to_owned());
        header.jwk = Some(self.jwk.clone());
        encode(
            &header,
            &ProofClaims {
                jti: uuid::Uuid::now_v7().to_string(),
                htm: method,
                htu: url,
                iat: now.unix_timestamp(),
                ath: access_token
                    .map(|token| URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))),
            },
            &self.encoding,
        )
        .context("sign transfer proof")
    }
}

#[derive(Serialize)]
struct ProofClaims<'a> {
    jti: String,
    htm: &'a str,
    htu: &'a str,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

fn public_jwk(signing: &SigningKey) -> Jwk {
    Jwk {
        common: CommonParameters {
            key_algorithm: Some(KeyAlgorithm::EdDSA),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
        }),
    }
}

fn generate_key_pem() -> Result<String> {
    let mut seed = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut seed)
        .context("read randomness from the operating system")?;
    let signing = SigningKey::from_bytes(&seed);
    Ok(signing
        .to_pkcs8_pem(LineEnding::LF)
        .context("encode signing key")?
        .to_string())
}

/// Whether this call stored the key, or found one already there.
enum Wrote {
    Created,
    AlreadyPresent,
}

/// Refuse a key any account but its owner can read.
///
/// This catches a key predating the owner-only creation above, one restored
/// from a backup, or one placed in a shared `--config-dir`. On platforms whose
/// permissions this cannot read there is nothing to check, and the caller is
/// responsible for pointing `--config-dir` somewhere private.
#[cfg(unix)]
fn ensure_owner_only(file: &std::fs::File, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    // Asked of the handle, not the name, so the permissions belong to the file
    // being read rather than to whatever the name resolves to a moment later.
    let mode = file
        .metadata()
        .with_context(|| format!("stat signing key {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "signing key {} is readable beyond its owner (mode {:o}); \
             restrict it with `chmod 600` before using it",
            path.display(),
            mode & 0o777
        );
    }
    Ok(())
}

/// Windows carries the same refusal, decided from the file's access-control
/// list rather than from mode bits.
///
/// The default location sits under the per-user profile, which the system
/// already restricts, so what this catches is a `--config-dir` somewhere a
/// second account can read — the case the flag's help asks the caller to avoid
/// and, until now, the only thing standing behind that request.
#[cfg(windows)]
fn ensure_owner_only(file: &std::fs::File, path: &Path) -> Result<()> {
    use crate::acl::Assessment;

    let current_user = crate::acl_windows::current_user_sid()?;
    let (owner, entries) = crate::acl_windows::security_of(file, path)?;

    match crate::acl::assess(&owner, &entries, &current_user) {
        Assessment::OwnerOnly => Ok(()),
        // Not a permissions problem, so there is no permissions fix to offer:
        // whoever owns the key can hand its list back to themselves whenever
        // they like, and may well know the private half already. The key is
        // theirs, and the only safe move is to stop using it.
        Assessment::OwnedByAnother { owner } => anyhow::bail!(
            "signing key {} is owned by {owner}, not by this account. An account that owns a key \
             can grant itself access to it at any time, and may already know its private half, so \
             a grant bound to it would not be bound to you. Delete it and let a fresh key be \
             created, or point --config-dir somewhere only you can write.",
            path.display(),
        ),
        Assessment::ReachableByOthers { principals } => {
            // `/inheritance:r` drops inherited entries and `/grant:r` replaces
            // this account's own, but neither touches an explicit entry naming
            // somebody else — so each offending principal is removed by name,
            // or the command would leave exactly what it was run to fix.
            let removals = principals
                .iter()
                .map(|sid| format!("/remove:g *{sid}"))
                .collect::<Vec<_>>()
                .join(" ");
            anyhow::bail!(
                "signing key {} can be read by {}; restrict it to your account with \
                 `icacls \"{}\" /inheritance:r {removals} /grant:r \"%USERNAME%\":F` \
                 before using it",
                path.display(),
                principals.join(", "),
                path.display(),
            )
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn ensure_owner_only(_file: &std::fs::File, _path: &Path) -> Result<()> {
    Ok(())
}

/// Create `staged` for writing, private from the instant it exists, failing if
/// something is already there.
///
/// Both platforms state this at creation rather than afterwards. A file created
/// permissively and tightened a moment later is readable in between, and on
/// Windows a reader admitted during that moment keeps the handle it opened —
/// revising an access list does not revoke access already granted. In a shared
/// directory that interval is enough to watch the key being written.
#[cfg(windows)]
fn create_private(staged: &Path) -> std::io::Result<std::fs::File> {
    crate::acl_windows::create_private_new(staged)
}

/// Create `staged` for writing, private from the instant it exists, failing if
/// something is already there. See the Windows counterpart for why the
/// permissions are set by the create call rather than after it.
#[cfg(not(windows))]
fn create_private(staged: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(staged)
}

/// Publish `contents` at `path` readable only by its owner, without replacing
/// a file that is already there.
///
/// The bytes are written to a staged sibling and then linked into place.
/// Creating `path` directly and writing into it would make the final name
/// visible while it was still empty, so a simultaneous first run could read a
/// truncated key and fail. Linking publishes a name that is complete and
/// owner-only from the instant it exists, and fails rather than replacing an
/// existing key, which is what makes the loser of a race adopt the winner's.
fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<Wrote> {
    use std::io::Write as _;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "signing key path has no parent directory",
        )
    })?;
    crate::config::create_private_dir(parent)?;

    let staged = parent.join(format!(".{}.partial", uuid::Uuid::now_v7()));

    let staged_write = (|| -> std::io::Result<()> {
        let mut file = create_private(&staged)?;
        file.write_all(contents)?;
        file.sync_all()
    })();
    if let Err(e) = staged_write {
        let _ = std::fs::remove_file(&staged);
        return Err(e);
    }

    // The link shares the staged file's inode, so the published name carries
    // its mode without a second permission step.
    let outcome = match std::fs::hard_link(&staged, path) {
        Ok(()) => Ok(Wrote::Created),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(Wrote::AlreadyPresent),
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_file(&staged);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7638 section 3.1 works its example against an RSA key; the OKP form
    /// this helper uses is specified by RFC 8037 section 2, whose own example
    /// pins both the key and the resulting thumbprint. Asserting that published
    /// value keeps our JWK member set and ordering honest — a thumbprint is a
    /// hash over the canonical JSON, so any stray member changes it.
    #[test]
    fn thumbprint_matches_rfc_8037_example() {
        let x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
        let jwk = Jwk {
            common: CommonParameters {
                key_algorithm: Some(KeyAlgorithm::EdDSA),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x: x.to_owned(),
            }),
        };
        assert_eq!(
            jwk.thumbprint(ThumbprintHash::SHA256),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    /// Losing the create race must not clobber the winner's key, and the loser
    /// has to notice: if it kept signing with the key it generated, the
    /// thumbprint it reported would bind a grant to a key no later run holds.
    #[test]
    fn an_existing_key_is_adopted_rather_than_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key.pem");
        let winner = HelperKey::load_or_create(&path).expect("first key");
        let stored = std::fs::read_to_string(&path).expect("read stored key");

        // Exactly what the losing side of a concurrent create does: it arrives
        // with a freshly generated key and finds the winner already on disk.
        let loser_pem = generate_key_pem().expect("competing key");
        assert_ne!(
            loser_pem, stored,
            "the two runs must generate distinct keys"
        );
        let loser = HelperKey::create_or_adopt(&path, &loser_pem).expect("adopt");
        assert!(matches!(
            write_private_file(&path, loser_pem.as_bytes()).expect("write"),
            Wrote::AlreadyPresent
        ));

        assert_eq!(
            loser.thumbprint(),
            winner.thumbprint(),
            "the loser must report the thumbprint of the key on disk, not the one it discarded"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("re-read"),
            stored,
            "the stored key must survive a second create attempt"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_new_key_and_its_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("mcp-files");
        let path = root.join("key.pem");
        HelperKey::load_or_create(&path).expect("create");

        let key_mode = std::fs::metadata(&path)
            .expect("stat key")
            .permissions()
            .mode();
        let dir_mode = std::fs::metadata(&root)
            .expect("stat dir")
            .permissions()
            .mode();

        assert_eq!(key_mode & 0o077, 0, "key mode {key_mode:o} leaks to others");
        assert_eq!(dir_mode & 0o077, 0, "dir mode {dir_mode:o} leaks to others");
    }

    /// Adopting is signing, so the adopt path owes the same permission check as
    /// the ordinary load. A key that appeared in a directory others can write
    /// is precisely the one not to trust.
    #[cfg(unix)]
    #[test]
    fn an_adopted_key_readable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key.pem");
        HelperKey::load_or_create(&path).expect("create");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("loosen");

        let arriving = generate_key_pem().expect("competing key");
        let error = match HelperKey::create_or_adopt(&path, &arriving) {
            Ok(_) => panic!("adopting a world-readable key defeats the holder binding"),
            Err(e) => e,
        };

        assert!(
            error.to_string().contains("readable beyond its owner"),
            "the refusal should say why: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_key_readable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key.pem");
        HelperKey::load_or_create(&path).expect("create");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("loosen");

        // Matched rather than `expect_err` so the key type needs no `Debug`:
        // deriving one on a struct holding private key material invites it into
        // a log line later.
        let error = match HelperKey::load_or_create(&path) {
            Ok(_) => panic!("a key others can read no longer protects the grant it is bound to"),
            Err(e) => e,
        };

        assert!(
            error.to_string().contains("readable beyond its owner"),
            "the refusal should say why: {error}"
        );
    }

    /// Drives the real interleaving rather than staging it: several first runs
    /// start together against an empty directory. Any of them may create the
    /// key; all of them have to end up signing with the same one. This fails if
    /// the published name is ever readable while incomplete, and if the losers
    /// keep the key they generated instead of the one on disk.
    #[test]
    fn simultaneous_first_runs_agree_on_one_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("key.pem");

        let thumbprints: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let path = path.clone();
                    scope.spawn(move || {
                        HelperKey::load_or_create(&path)
                            .expect("a concurrent first run must not fail")
                            .thumbprint()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("thread"))
                .collect()
        });

        let first = &thumbprints[0];
        assert!(
            thumbprints.iter().all(|t| t == first),
            "every run must report the key that reached disk: {thumbprints:?}"
        );
        assert_eq!(
            HelperKey::load_or_create(&path)
                .expect("reload")
                .thumbprint(),
            *first,
            "a later run must agree with the ones that raced"
        );
    }

    #[test]
    fn publishing_leaves_no_staged_files_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key.pem");

        HelperKey::load_or_create(&path).expect("create");
        // A second attempt takes the already-present branch, which also stages.
        write_private_file(&path, b"unused").expect("second attempt");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .filter(|name| name.to_string_lossy() != "key.pem")
            .collect();
        assert!(leftovers.is_empty(), "staged files remained: {leftovers:?}");
    }

    #[test]
    fn key_is_stable_across_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key.pem");

        let first = HelperKey::load_or_create(&path).expect("create");
        let second = HelperKey::load_or_create(&path).expect("reload");

        assert_eq!(first.thumbprint(), second.thumbprint());
    }

    #[test]
    fn proof_omits_ath_when_no_token_is_sent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = HelperKey::load_or_create(&dir.path().join("key.pem")).expect("key");

        let proof = key
            .proof(
                "POST",
                "https://gateway.example/n/credentials",
                None,
                OffsetDateTime::now_utc(),
            )
            .expect("proof");

        let claims = decode_claims(&proof);
        assert!(
            claims.get("ath").is_none(),
            "a proof for a tokenless request must not carry ath"
        );
        assert_eq!(claims["htm"], "POST");
    }

    #[test]
    fn proof_binds_the_access_token_when_one_is_sent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = HelperKey::load_or_create(&dir.path().join("key.pem")).expect("key");

        let proof = key
            .proof(
                "PUT",
                "https://gateway.example/n/content",
                Some("token-value"),
                OffsetDateTime::now_utc(),
            )
            .expect("proof");

        let claims = decode_claims(&proof);
        assert_eq!(
            claims["ath"],
            URL_SAFE_NO_PAD.encode(Sha256::digest(b"token-value"))
        );
    }

    #[test]
    fn each_proof_carries_a_distinct_identifier() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = HelperKey::load_or_create(&dir.path().join("key.pem")).expect("key");
        let now = OffsetDateTime::now_utc();
        let url = "https://gateway.example/n/content";

        let first = decode_claims(&key.proof("PUT", url, None, now).expect("proof"));
        let second = decode_claims(&key.proof("PUT", url, None, now).expect("proof"));

        assert_ne!(
            first["jti"], second["jti"],
            "replayed identifiers are refused, so each proof needs its own"
        );
    }

    fn decode_claims(jwt: &str) -> serde_json::Value {
        let payload = jwt.split('.').nth(1).expect("proof has a payload segment");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("payload decodes"))
            .expect("payload is JSON")
    }
}
