fn main() {
    let catalog = alani_terminal::terminal_catalog();
    println!(
        "{} {} modules={} features=0x{:x}",
        catalog.repository,
        catalog.version,
        alani_terminal::module_names().len(),
        catalog.features
    );
}
