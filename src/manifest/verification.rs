//! Machine-checked proofs, with Kani, of what makes a manifest well formed: an option set is the
//! letters it was given or nothing, and a widening option is always one the manifest declares.

use super::*;

/// Falsification: replayable `falsifications/manifest.verification.an_option_set_is_its_letters_or_nothing.patch`
/// For any letters up to one more than [`MAXIMUM_DECLARED_SHORT_OPTIONS`], [`ShortOptions::try_new`]
/// answers a set exactly when there are at most that many, each an ASCII letter or digit and none
/// twice, and the set it answers holds those letters in the order given.
#[kani::proof]
#[kani::unwind(18)]
fn an_option_set_is_its_letters_or_nothing() {
    const MOST: usize = MAXIMUM_DECLARED_SHORT_OPTIONS + 1;
    let bytes: [u8; MOST] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= MOST);
    let letters = &bytes[..length];
    let mut lawful = length <= MAXIMUM_DECLARED_SHORT_OPTIONS;
    for (i, l) in letters.iter().enumerate() {
        lawful &= l.is_ascii_alphanumeric() && !letters[..i].contains(l);
    }
    match ShortOptions::try_new(letters) {
        Some(options) => {
            assert!(lawful);
            assert_eq!(options.letters(), letters);
        }
        None => assert!(!lawful),
    }
    kani::cover!(
        lawful && length == MAXIMUM_DECLARED_SHORT_OPTIONS,
        "the longest set"
    );
}

/// Falsification: replayable `falsifications/manifest.verification.a_manifest_is_well_formed_exactly_when_its_widening_option_is_declared.patch`
/// For any directory declaration and any set of up to three option letters,
/// [`Manifest::is_well_formed`] answers true exactly when the directory grant names no widening
/// option or names one the manifest declares, wherever in the set that letter sits.
#[kani::proof]
#[kani::unwind(5)]
fn a_manifest_is_well_formed_exactly_when_its_widening_option_is_declared() {
    let bytes: [u8; 3] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= 3);
    let Some(short_options) = ShortOptions::try_new(&bytes[..length]) else {
        return;
    };
    let option: Option<u8> = kani::any();
    let directory = if kani::any() {
        DirectoryGrantDeclaration::Required {
            subtree_option: option,
        }
    } else {
        DirectoryGrantDeclaration::Forbidden
    };
    let m = Manifest {
        program_argument: ProgramArgumentDeclaration::Forbidden,
        memory_grant: MemoryGrantDeclaration::Forbidden,
        file: FileGrantDeclaration::Forbidden,
        directory,
        short_options,
        output: OutputDeclaration::Bytes,
        input: InputDeclaration::Forbidden,
        reports: true,
        interruptible: false,
        clock: false,
        domain: false,
        configuration: false,
        entropy: false,
        network: false,
        machine: false,
        share: false,
        reboot: false,
        sync: false,
        installer: false,
        catalog: false,
        indexes: IndexStoreDeclaration::Forbidden,
        activation_directory: false,
        console_input: false,
        startup: StartupContract::Native,
    };
    let declared = match directory {
        DirectoryGrantDeclaration::Required {
            subtree_option: Some(letter),
        } => short_options.letters().contains(&letter),
        _ => true,
    };
    assert_eq!(m.is_well_formed(), declared);
    kani::cover!(
        declared && length == 3 && option == Some(bytes[2]),
        "the widening option is the last letter"
    );
}
