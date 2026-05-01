//! `parser` module boundary.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParserDescriptor<'a> {
    pub name: &'a str,
    pub version: u32,
}

impl<'a> ParserDescriptor<'a> {
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
