//! Machine-checked proofs, with Kani, that narrowing a manifest by its verb never widens it.

use super::*;
use crate::{
    DirectoryGrantDeclaration, FileGrantDeclaration, InputDeclaration, MemoryGrantDeclaration,
    OutputDeclaration, ProgramArgumentDeclaration, ShortOptions, StartupContract,
};

/// Any index store declaration.
fn any_index_store() -> IndexStoreDeclaration {
    match kani::any::<u8>() % 3 {
        0 => IndexStoreDeclaration::Forbidden,
        1 => IndexStoreDeclaration::ReadOnly,
        _ => IndexStoreDeclaration::ReadWrite,
    }
}

/// How much of the index store a declaration holds: none, reading, reading and writing.
fn index_rank(d: IndexStoreDeclaration) -> u8 {
    match d {
        IndexStoreDeclaration::Forbidden => 0,
        IndexStoreDeclaration::ReadOnly => 1,
        IndexStoreDeclaration::ReadWrite => 2,
    }
}

/// Any set of authorities a verb table may hand out.
fn any_authorities() -> ManifestAuthorities {
    let bits: u16 = kani::any();
    kani::assume(bits & !ManifestAuthorities::ALL.bits() == 0);
    ManifestAuthorities(bits)
}

/// [`narrow_by_verb`] over the first `entries` of `table` and the first `length` bytes of `bytes`.
/// Each call is made with slices of a fixed length and a single origin, so the model checker
/// unrolls every loop inside it to a known bound.
fn narrowed(
    m: &Manifest,
    table: &[VerbGrant; 2],
    entries: u8,
    bytes: &[u8; 7],
    length: Option<usize>,
) -> Manifest {
    match entries {
        0 => narrow_by_verb(m, &[], length.map(|_| &bytes[..0])),
        1 => narrowed_by(m, &table[..1], bytes, length),
        _ => narrowed_by(m, &table[..], bytes, length),
    }
}

/// [`narrow_by_verb`] over `verbs` and the first `length` bytes of `bytes`, one fixed length per
/// call.
fn narrowed_by(
    m: &Manifest,
    verbs: &[VerbGrant],
    bytes: &[u8; 7],
    length: Option<usize>,
) -> Manifest {
    match length {
        None => narrow_by_verb(m, verbs, None),
        Some(0) => narrow_by_verb(m, verbs, Some(&bytes[..0])),
        Some(1) => narrow_by_verb(m, verbs, Some(&bytes[..1])),
        Some(2) => narrow_by_verb(m, verbs, Some(&bytes[..2])),
        Some(3) => narrow_by_verb(m, verbs, Some(&bytes[..3])),
        Some(4) => narrow_by_verb(m, verbs, Some(&bytes[..4])),
        Some(5) => narrow_by_verb(m, verbs, Some(&bytes[..5])),
        Some(6) => narrow_by_verb(m, verbs, Some(&bytes[..6])),
        Some(_) => narrow_by_verb(m, verbs, Some(&bytes[..7])),
    }
}

/// Falsification: replayable `falsifications/verbs.verification.a_verb_never_widens_a_manifest.patch`
/// For any manifest, a verb table of up to two entries (one verb and the same verb with an
/// option) granting anything, and any line verb of up to seven bytes or none,
/// [`narrow_by_verb`] keeps each authority only when the manifest declares it and the verb's
/// entry names it, never holds more of the index store than the manifest declares, and changes no
/// field a verb cannot choose. An empty table returns the manifest as it is.
#[kani::proof]
#[kani::unwind(18)]
fn a_verb_never_widens_a_manifest() {
    let m = Manifest {
        program_argument: ProgramArgumentDeclaration::Forbidden,
        memory_grant: MemoryGrantDeclaration::Forbidden,
        file: FileGrantDeclaration::Forbidden,
        directory: DirectoryGrantDeclaration::Forbidden,
        short_options: ShortOptions::new(b"u"),
        output: OutputDeclaration::Bytes,
        input: InputDeclaration::Forbidden,
        reports: kani::any(),
        interruptible: kani::any(),
        clock: kani::any(),
        domain: kani::any(),
        configuration: kani::any(),
        entropy: kani::any(),
        network: kani::any(),
        machine: kani::any(),
        share: kani::any(),
        reboot: kani::any(),
        sync: kani::any(),
        installer: kani::any(),
        catalog: kani::any(),
        indexes: any_index_store(),
        activation_directory: kani::any(),
        console_input: kani::any(),
        startup: StartupContract::Std,
    };
    let table = [
        VerbGrant {
            verb: "list",
            authorities: any_authorities(),
        },
        VerbGrant {
            verb: "list -u",
            authorities: any_authorities(),
        },
    ];
    let entries: u8 = kani::any();
    kani::assume(entries <= 2);
    let bytes: [u8; 7] = kani::any();
    // How many bytes of `bytes` the line's verb is, or `None` for a line with no verb.
    let length: Option<usize> = kani::any();
    kani::assume(length.is_none_or(|l| l <= bytes.len()));

    let n = narrowed(&m, &table, entries, &bytes, length);
    if entries == 0 {
        assert_eq!(n, m);
        return;
    }
    // What the verb's entry grants: the whole verb first, then its first word alone.
    let is = |want: &[u8]| length == Some(want.len()) && bytes[..want.len()] == *want;
    let first_word_is_list =
        length.is_some_and(|l| l >= 4 && bytes[..4] == *b"list" && (l == 4 || bytes[4] == b' '));
    let g = if entries == 2 && is(b"list -u") {
        table[1].authorities
    } else if first_word_is_list {
        table[0].authorities
    } else {
        ManifestAuthorities::NONE
    };
    for (kept, declared, bit) in [
        (n.clock, m.clock, ManifestAuthorities::CLOCK),
        (
            n.configuration,
            m.configuration,
            ManifestAuthorities::CONFIGURATION,
        ),
        (n.entropy, m.entropy, ManifestAuthorities::ENTROPY),
        (n.network, m.network, ManifestAuthorities::NETWORK),
        (n.domain, m.domain, ManifestAuthorities::DOMAIN),
        (n.machine, m.machine, ManifestAuthorities::MACHINE),
        (n.share, m.share, ManifestAuthorities::SHARE),
        (n.installer, m.installer, ManifestAuthorities::INSTALLER),
        (n.catalog, m.catalog, ManifestAuthorities::CATALOG),
        (
            n.activation_directory,
            m.activation_directory,
            ManifestAuthorities::ACTIVATION,
        ),
        (
            n.console_input,
            m.console_input,
            ManifestAuthorities::INSTALLER,
        ),
    ] {
        assert_eq!(kept, declared && g.contains(bit));
    }
    assert!(index_rank(n.indexes) <= index_rank(m.indexes));
    if n.indexes != IndexStoreDeclaration::Forbidden {
        assert!(g.contains(ManifestAuthorities::INDEXES));
    }
    if n.indexes == IndexStoreDeclaration::ReadWrite {
        assert!(g.contains(ManifestAuthorities::INDEXES_WRITE));
    }
    assert_eq!(
        (n.reports, n.interruptible, n.reboot, n.sync),
        (m.reports, m.interruptible, m.reboot, m.sync)
    );
    assert_eq!(
        (n.program_argument, n.memory_grant, n.file, n.directory),
        (m.program_argument, m.memory_grant, m.file, m.directory)
    );
    assert_eq!(
        (n.short_options, n.output, n.input, n.startup),
        (m.short_options, m.output, m.input, m.startup)
    );
    kani::cover!(
        entries == 2 && is(b"list -u") && n.indexes == IndexStoreDeclaration::ReadWrite,
        "the two-word verb holds the index store to write"
    );
}
