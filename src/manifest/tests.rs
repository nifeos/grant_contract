//! Tests of the manifest types.

use crate::*;

// ---- survivor triage of the 2026-10-03 census ---------------------------------------------

/// An option set is at most sixteen distinct letters or digits, and sixteen is allowed.
#[test]
fn an_option_set_may_hold_exactly_its_maximum_and_no_repeat() {
    let sixteen = b"abcdefghijklmnop";
    assert_eq!(sixteen.len(), MAXIMUM_DECLARED_SHORT_OPTIONS);
    assert!(ShortOptions::try_new(sixteen).is_some());
    assert!(ShortOptions::try_new(b"abcdefghijklmnopq").is_none());
    assert!(ShortOptions::try_new(b"aa").is_none());
    assert!(ShortOptions::try_new(b"aba").is_none());
    assert!(ShortOptions::try_new(b"ab").is_some());
    assert!(ShortOptions::try_new(b"a-").is_none());
}

fn a_manifest_with(directory: DirectoryGrantDeclaration, options: &[u8]) -> Manifest {
    Manifest {
        program_argument: ProgramArgumentDeclaration::Forbidden,
        memory_grant: MemoryGrantDeclaration::Forbidden,
        file: FileGrantDeclaration::Forbidden,
        directory,
        short_options: ShortOptions::new(options),
        output: OutputDeclaration::Silent,
        input: InputDeclaration::Forbidden,
        reports: false,
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
    }
}

/// **A manifest is well formed when its widening option is one it declares, wherever in the list
/// that letter sits.** The first, a middle and the last letter are all found; a letter that is
/// not declared, in a list of any length including none, is refused (and never reads past the
/// end of the list).
#[test]
fn a_widening_option_must_be_one_the_manifest_declares() {
    let widening = |letter| DirectoryGrantDeclaration::Required {
        subtree_option: Some(letter),
    };
    for letter in *b"rfi" {
        assert!(a_manifest_with(widening(letter), b"rfi").is_well_formed());
    }
    assert!(!a_manifest_with(widening(b'x'), b"rfi").is_well_formed());
    assert!(!a_manifest_with(widening(b'r'), b"").is_well_formed());
    assert!(a_manifest_with(widening(b'r'), b"r").is_well_formed());
    let no_widening = DirectoryGrantDeclaration::Required {
        subtree_option: None,
    };
    assert!(a_manifest_with(no_widening, b"").is_well_formed());
    assert!(a_manifest_with(DirectoryGrantDeclaration::Forbidden, b"").is_well_formed());
}

/// **Only a stream of bytes has anything for `>` and `|` to substitute, and only a declared second
/// stream has a slot for `2>`.**
#[test]
fn an_output_declaration_answers_for_its_operators() {
    let diagnostics = OutputDeclaration::BytesAndDiagnostics { slot: 61 };
    assert!(OutputDeclaration::Bytes.is_byte_stream());
    assert!(diagnostics.is_byte_stream());
    assert!(!OutputDeclaration::Silent.is_byte_stream());
    assert_eq!(diagnostics.diagnostics_slot(), Some(61));
    assert_eq!(OutputDeclaration::Bytes.diagnostics_slot(), None);
    assert_eq!(OutputDeclaration::Silent.diagnostics_slot(), None);
}

/// **Only a program that declares `Words` hears the line as its argv.**
#[test]
fn only_a_words_declaration_hears_words() {
    assert!(ProgramArgumentDeclaration::Words(WordGrant::ReadOnly).hears_words());
    assert!(!ProgramArgumentDeclaration::Required.hears_words());
    assert!(!ProgramArgumentDeclaration::Forbidden.hears_words());
}

/// **Each word grant asks for exactly its rights**, as the file service's bits: enumerate (0),
/// read (1), write (2), create (3) and descend (5). Each grant adds to the one before it.
#[test]
fn each_word_grant_asks_for_exactly_its_rights() {
    let read = 1 | 1 << 1 | 1 << 5;
    assert_eq!(WordGrant::ReadOnly.rights(), read);
    assert_eq!(WordGrant::ReadWrite.rights(), read | 1 << 2);
    assert_eq!(WordGrant::Create.rights(), read | 1 << 2 | 1 << 3);
}

/// **The index store opens with a reader's rights to read and a creator's to write**, and a
/// program that declares no store opens nothing.
#[test]
fn the_index_store_opens_with_the_rights_it_declares() {
    assert_eq!(IndexStoreDeclaration::Forbidden.rights(), None);
    assert_eq!(
        IndexStoreDeclaration::ReadOnly.rights(),
        Some(WordGrant::ReadOnly.rights())
    );
    assert_eq!(
        IndexStoreDeclaration::ReadWrite.rights(),
        Some(WordGrant::Create.rights())
    );
}

/// **An option set written in source that repeats a letter is refused**, by a panic at run time
/// and a compile error in a `const`.
#[test]
#[should_panic(expected = "an option set is at most 16 distinct ASCII letters or digits")]
fn a_repeated_letter_in_source_is_refused() {
    let letters: &[u8] = core::hint::black_box(b"aa");
    let _ = ShortOptions::new(letters);
}
