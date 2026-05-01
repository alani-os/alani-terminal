#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_terminal::repository_name(), "alani-terminal");
    assert!(!alani_terminal::module_names().is_empty());
}
