use clap::ValueEnum;

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum, strum::Display, strum::EnumIter)]
pub enum Segment {
    #[value(name = "4KB", alias = "4kb", alias = "4KiB", alias = "4kib")]
    FourKilobytes,
    #[value(name = "64KB", alias = "64kb", alias = "64KiB", alias = "64kib")]
    SixtyFourKilobytes,
    #[value(name = "1MB", alias = "1mb", alias = "1MiB", alias = "1mib")]
    OneMegabyte,
    #[value(name = "4MB", alias = "4mb", alias = "4MiB", alias = "4mib")]
    FourMegabytes,
}
impl From<Segment> for navajo::aead::Segment {
    fn from(value: Segment) -> Self {
        match value {
            Segment::FourKilobytes => navajo::aead::Segment::FourKilobytes,
            Segment::SixtyFourKilobytes => navajo::aead::Segment::SixtyFourKilobytes,
            Segment::OneMegabyte => navajo::aead::Segment::OneMegabyte,
            Segment::FourMegabytes => navajo::aead::Segment::FourMegabytes,
        }
    }
}
