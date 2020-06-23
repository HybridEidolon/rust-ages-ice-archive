//! Operations over SEGA ICE archives, used in _Phantasy Star Online 2_.

mod read;
mod write;

pub use self::read::{IceArchive, IceFile, GroupNotUnpackedError};
pub use self::write::{IceWriter, IceFileWriter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// One of the two file groups in an ICE archive.
pub enum Group {
    Group1,
    Group2,
}

impl ::std::fmt::Display for Group {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let index = match self {
            Group::Group1 => 1,
            Group::Group2 => 2,
        };
        fmt.write_fmt(format_args!("Group {}", index))
    }
}
