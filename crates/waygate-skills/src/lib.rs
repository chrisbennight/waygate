//! Verified Agent Skills catalog snapshots and source seams.
//!
//! Skill repository access remains outside this crate. A source indexes an
//! immutable revision into a [`SkillCatalogSnapshot`], while resource bytes are
//! fetched through that snapshot only when requested. Refresh publishes a
//! complete metadata snapshot atomically and leaves the previous snapshot
//! active when acquisition or validation fails.

pub mod distribution;
mod model;
pub mod review;
mod source;
mod validate;

pub use model::{
    CatalogManifest, CatalogSkill, CatalogSourceIdentity, LoadedSkillResource,
    SkillApprovalBinding, SkillApprovalPurpose, SkillCatalogSnapshot, SkillEntry,
    SkillResourceDescriptor, SkillResourceIdentity, SkillRevisionIdentity, CATALOG_SCHEMA_VERSION,
    CODE_MODE_METADATA_KEY,
};
pub use source::{
    InMemorySkillResourceLoader, ReloadableSkillCatalog, SkillCatalogSource, SkillCatalogStatus,
    SkillResourceLoadError, SkillResourceLoader, SkillSourceError,
};
pub use validate::{
    parse_skill_frontmatter, sha256_digest, valid_skill_name, verify_catalog_snapshot,
    verify_in_memory_catalog, CatalogValidationError, SkillFrontmatterError,
    MAX_SKILL_RESOURCE_ENTRIES, MAX_SKILL_TOTAL_BYTES,
};
