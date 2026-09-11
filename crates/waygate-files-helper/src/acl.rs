//! Whether a Windows access-control list leaves the signing key owner-only.
//!
//! Windows has no mode bits, so the Unix `0600` check has no direct
//! counterpart: what decides who can get at the key is an owner plus a list of
//! entries naming security identifiers. The *decision* about those lives here
//! rather than beside the calls that read them, so it can be exercised wherever
//! the tests run instead of only on the platform it governs.
//!
//! Only access-allowed entries are considered. A deny entry that would have
//! taken an access back is not credited, so a list carrying one may be refused
//! when it did not have to be. That direction is the safe one: the cost is a
//! message naming the fix, where the opposite would be a key silently trusted
//! while another account could read it.

/// One access-allowed entry, reduced to what the decision needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedPrincipal {
    /// The security identifier in string form, e.g. `S-1-5-21-…-1001`.
    pub sid: String,
    /// Whether the entry confers any hold over the key worth objecting to.
    ///
    /// Reading the bytes is the obvious one, but it is not the only one that
    /// matters. An account that can *write* the file can put a key it knows
    /// where ours was, and one that can rewrite the list or take ownership can
    /// grant itself the read it does not yet have. All three end the same way,
    /// so the caller reports them the same way.
    pub confers_access: bool,
}

/// Local SYSTEM.
const LOCAL_SYSTEM: &str = "S-1-5-18";
/// The built-in Administrators group.
const BUILTIN_ADMINISTRATORS: &str = "S-1-5-32-544";

/// Access-mask bits that give their holder nothing worth objecting to.
///
/// Stated as an allowlist, because the question is not "can this principal read
/// the key" but "does this principal have any hold on it", and the ways to hold
/// a file outnumber the ways to read one. Writing it replaces the key with one
/// the writer knows; rewriting its list or taking its ownership grants the read
/// that was withheld; deleting it invites a replacement. Naming the harmful bits
/// would mean naming all of those and hoping none was forgotten, so the harmless
/// ones are named instead and everything else counts — including bits nobody has
/// thought of yet.
///
/// What is allowed here is the right to see that the file exists and to read its
/// metadata and its list, none of which discloses or disturbs the key.
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_READ_EA: u32 = 0x0008;
const HARMLESS: u32 = READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_EA;

/// Whether an access mask gives its holder a hold on the key.
///
/// Lives here rather than beside the call that reads the mask so that the rule
/// deciding it is exercised wherever the tests run. It is a pure function of a
/// number, and it is the rule the whole Windows verdict rests on.
pub fn mask_confers_access(mask: u32) -> bool {
    mask & !HARMLESS != 0
}

/// Principals whose presence says nothing about exposure.
///
/// Both can already take ownership of any file on the machine, so refusing a
/// key because they appear would reject the ordinary per-user profile — the
/// location this helper defaults to — while denying neither any reach it does
/// not already have.
fn is_unavoidable(sid: &str) -> bool {
    sid.eq_ignore_ascii_case(LOCAL_SYSTEM) || sid.eq_ignore_ascii_case(BUILTIN_ADMINISTRATORS)
}

/// What is wrong with a key's security descriptor, if anything.
#[derive(Debug, PartialEq, Eq)]
pub enum Assessment {
    /// This account owns the key and no other principal has any hold on it.
    OwnerOnly,
    /// Another account owns the key, so it decides who may read it and can
    /// re-grant itself at any time. Its access list says nothing about that.
    OwnedByAnother { owner: String },
    /// This account owns the key, but the listed principals can reach it —
    /// by reading it, replacing it, or granting themselves the access they
    /// lack.
    ReachableByOthers { principals: Vec<String> },
}

/// Judge a key's security descriptor.
///
/// Ownership is checked before the access list because it outranks it. A
/// Windows file's owner may rewrite its list whenever it likes, so a key owned
/// by somebody else is theirs regardless of what the list says today. That is
/// not a hypothetical ordering concern: an account that can write to a shared
/// configuration directory can place a key whose private half it knows and give
/// the list away to its victim, and a check that read only the list would find
/// nothing to object to and adopt it.
///
/// Unix needs no equivalent because it will not let one account create a file
/// owned by another.
pub fn assess(owner: &str, entries: &[AllowedPrincipal], current_user: &str) -> Assessment {
    // An unavoidable principal is accepted as owner for the same reason it is
    // accepted in the list: it can take ownership of anything on the machine, so
    // refusing it withholds nothing. It also happens on ordinary machines —
    // Windows may hand a new object to the Administrators group rather than to
    // the account that created it, and refusing that would leave an
    // administrator's very first run creating a key it then refuses forever.
    if !owner.eq_ignore_ascii_case(current_user) && !is_unavoidable(owner) {
        return Assessment::OwnedByAnother {
            owner: owner.to_owned(),
        };
    }

    let principals = principals_beyond_owner(entries, current_user);
    if principals.is_empty() {
        Assessment::OwnerOnly
    } else {
        Assessment::ReachableByOthers { principals }
    }
}

/// The principals besides `owner` that this list gives a hold over the key.
///
/// An empty result means the key is as private as a `0600` file is on Unix.
fn principals_beyond_owner(entries: &[AllowedPrincipal], owner: &str) -> Vec<String> {
    let mut found: Vec<String> = entries
        .iter()
        .filter(|entry| entry.confers_access)
        .map(|entry| entry.sid.clone())
        .filter(|sid| !sid.eq_ignore_ascii_case(owner) && !is_unavoidable(sid))
        .collect();
    found.sort();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plausible per-user SID; the machine portion is irrelevant to the
    /// decision, which compares whole strings.
    const OWNER: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
    const ANOTHER_USER: &str = "S-1-5-21-1004336348-1177238915-682003330-1002";
    /// The `Users` group — the one that actually turns up on a shared location.
    const USERS: &str = "S-1-5-32-545";

    fn reader(sid: &str) -> AllowedPrincipal {
        AllowedPrincipal {
            sid: sid.to_owned(),
            confers_access: true,
        }
    }

    #[test]
    fn an_owner_only_list_names_nobody_else() {
        assert!(principals_beyond_owner(&[reader(OWNER)], OWNER).is_empty());
    }

    #[test]
    fn the_profile_default_is_accepted() {
        // What a file inheriting the per-user profile's own ACL looks like.
        // Refusing this would reject the location the helper defaults to.
        let entries = [
            reader(OWNER),
            reader(LOCAL_SYSTEM),
            reader(BUILTIN_ADMINISTRATORS),
        ];

        assert!(
            principals_beyond_owner(&entries, OWNER).is_empty(),
            "SYSTEM and Administrators can take ownership regardless; \
             naming them is not additional exposure"
        );
    }

    #[test]
    fn another_local_account_is_reported() {
        let found = principals_beyond_owner(&[reader(OWNER), reader(ANOTHER_USER)], OWNER);

        assert_eq!(
            found,
            vec![ANOTHER_USER.to_owned()],
            "a second account with a hold on the key defeats the holder binding"
        );
    }

    /// The exposure the issue describes: a `--config-dir` in a shared location,
    /// where the key inherits an ACL naming a group rather than a person.
    #[test]
    fn a_group_with_a_hold_on_the_key_is_reported() {
        let found = principals_beyond_owner(&[reader(OWNER), reader(USERS)], OWNER);

        assert_eq!(found, vec![USERS.to_owned()]);
    }

    /// Not every entry is an objection. One conferring nothing but the right to
    /// see that the file exists leaves the key alone, and reporting it would
    /// send people chasing an entry that costs them nothing. Which masks fall on
    /// which side is the caller's judgement; this only honours it.
    #[test]
    fn an_entry_conferring_nothing_is_not_reported() {
        let entries = [
            reader(OWNER),
            AllowedPrincipal {
                sid: ANOTHER_USER.to_owned(),
                confers_access: false,
            },
        ];

        assert!(principals_beyond_owner(&entries, OWNER).is_empty());
    }

    #[test]
    fn every_extra_principal_is_named_once() {
        let entries = [
            reader(ANOTHER_USER),
            reader(USERS),
            // The same principal may appear more than once across ACEs
            // carrying different masks; the caller wants the set, not the list.
            reader(ANOTHER_USER),
        ];

        let found = principals_beyond_owner(&entries, OWNER);

        assert_eq!(found, vec![ANOTHER_USER.to_owned(), USERS.to_owned()]);
    }

    /// SID strings are conventionally upper case, but they are compared here
    /// against a value that came back from a separate call. Case must not be
    /// what decides whether the key is trusted.
    #[test]
    fn owner_matching_ignores_case() {
        let lowered = OWNER.to_lowercase();
        assert!(principals_beyond_owner(&[reader(&lowered)], OWNER).is_empty());
    }

    #[test]
    fn an_empty_list_grants_nobody_anything() {
        assert!(principals_beyond_owner(&[], OWNER).is_empty());
    }

    #[test]
    fn a_key_this_account_owns_and_nobody_else_reads_is_accepted() {
        assert_eq!(
            assess(OWNER, &[reader(OWNER)], OWNER),
            Assessment::OwnerOnly
        );
    }

    /// A key placed by another account, with its list handed to the victim.
    /// Reading the list alone finds nothing to object to — every entry names the
    /// account doing the checking — so ownership is what has to catch this. The
    /// planted key's private half is known to whoever planted it, and signing
    /// with it would bind grants to a key that account can redeem.
    #[test]
    fn a_key_owned_by_another_account_is_refused_however_its_list_reads() {
        let planted = assess(ANOTHER_USER, &[reader(OWNER)], OWNER);

        assert_eq!(
            planted,
            Assessment::OwnedByAnother {
                owner: ANOTHER_USER.to_owned()
            },
            "an access list that names only the victim still leaves the owner able to rewrite it"
        );
    }

    #[test]
    fn ownership_outranks_the_access_list() {
        // Owned by someone else *and* readable by someone else: the report
        // should name the ownership problem, because fixing the list would not
        // fix it.
        let both = assess(ANOTHER_USER, &[reader(OWNER), reader(USERS)], OWNER);

        assert!(matches!(both, Assessment::OwnedByAnother { .. }));
    }

    #[test]
    fn an_owned_key_others_can_read_reports_them() {
        assert_eq!(
            assess(OWNER, &[reader(OWNER), reader(USERS)], OWNER),
            Assessment::ReachableByOthers {
                principals: vec![USERS.to_owned()]
            }
        );
    }

    #[test]
    fn ownership_matching_ignores_case() {
        assert_eq!(
            assess(&OWNER.to_lowercase(), &[reader(OWNER)], OWNER),
            Assessment::OwnerOnly
        );
    }

    /// Windows may hand a new object to the Administrators group rather than to
    /// the account that created it. Refusing that would mean an administrator's
    /// first run creates a key and then refuses it on every later run, with no
    /// way out — and it would withhold nothing, since that group can take
    /// ownership of the key whenever it likes.
    #[test]
    fn an_unavoidable_principal_is_accepted_as_owner() {
        assert_eq!(
            assess(BUILTIN_ADMINISTRATORS, &[reader(OWNER)], OWNER),
            Assessment::OwnerOnly
        );
        assert_eq!(
            assess(LOCAL_SYSTEM, &[reader(OWNER)], OWNER),
            Assessment::OwnerOnly
        );
    }

    /// The mask rule the whole Windows verdict rests on. Written against the
    /// numeric rights rather than a re-derivation of the allowlist, so a change
    /// to that allowlist has to agree with what each right actually means.
    mod mask {
        use super::super::mask_confers_access;

        const FILE_READ_DATA: u32 = 0x0001;
        const FILE_WRITE_DATA: u32 = 0x0002;
        const FILE_APPEND_DATA: u32 = 0x0004;
        const FILE_WRITE_EA: u32 = 0x0010;
        const FILE_EXECUTE: u32 = 0x0020;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
        const DELETE: u32 = 0x0001_0000;
        const READ_CONTROL: u32 = 0x0002_0000;
        const WRITE_DAC: u32 = 0x0004_0000;
        const WRITE_OWNER: u32 = 0x0008_0000;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const FILE_READ_EA: u32 = 0x0008;
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;
        const GENERIC_ALL: u32 = 0x1000_0000;
        const GENERIC_EXECUTE: u32 = 0x2000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const GENERIC_READ: u32 = 0x8000_0000;

        #[test]
        fn reading_the_bytes_is_a_hold() {
            assert!(mask_confers_access(FILE_READ_DATA));
            assert!(mask_confers_access(GENERIC_READ));
            assert!(mask_confers_access(GENERIC_ALL));
        }

        /// Writing is as good as reading here: an account that can overwrite the
        /// key can put one it knows in place of ours, and every grant afterwards
        /// binds to a key it can redeem.
        #[test]
        fn replacing_the_bytes_is_a_hold() {
            assert!(mask_confers_access(FILE_WRITE_DATA));
            assert!(mask_confers_access(FILE_APPEND_DATA));
            assert!(mask_confers_access(GENERIC_WRITE));
            assert!(mask_confers_access(DELETE));
        }

        /// Neither of these reads the key today, and both can arrange to.
        #[test]
        fn taking_control_is_a_hold() {
            assert!(mask_confers_access(WRITE_DAC));
            assert!(mask_confers_access(WRITE_OWNER));
        }

        #[test]
        fn looking_at_the_file_without_touching_it_is_not() {
            assert!(!mask_confers_access(READ_CONTROL));
            assert!(!mask_confers_access(SYNCHRONIZE));
            assert!(!mask_confers_access(FILE_READ_ATTRIBUTES));
            assert!(!mask_confers_access(FILE_READ_EA));
            assert!(!mask_confers_access(
                READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_EA
            ));
        }

        #[test]
        fn an_empty_mask_grants_nothing() {
            assert!(!mask_confers_access(0));
        }

        /// The allowlist exists so that a right nobody considered counts against
        /// the key rather than slipping past. Metadata writes and execute are
        /// real rights that were never enumerated as harmful; an undefined bit
        /// stands in for whatever comes next.
        #[test]
        fn anything_not_named_harmless_counts() {
            assert!(mask_confers_access(FILE_WRITE_EA));
            assert!(mask_confers_access(FILE_WRITE_ATTRIBUTES));
            assert!(mask_confers_access(FILE_EXECUTE));
            assert!(mask_confers_access(GENERIC_EXECUTE));
            assert!(mask_confers_access(0x0000_4000));
        }

        /// A harmless right alongside a harmful one must not launder it.
        #[test]
        fn a_harmless_bit_does_not_excuse_a_harmful_one() {
            assert!(mask_confers_access(READ_CONTROL | FILE_WRITE_DATA));
            assert!(mask_confers_access(SYNCHRONIZE | FILE_READ_DATA));
        }
    }
}
