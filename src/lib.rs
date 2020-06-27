//! Operations over SEGA ICE archives, used in _Phantasy Star Online 2_.
//!
//! Currently, only ICE versions 3 and 4 are supported for reading and writing.
//! These are the only kinds of ICE files in the game client and protocol, so it
//! should be usable for all available ICE files.
//!
//! # Examples
//!
//! Reading an ICE file:
//!
//! ```no_run
//! use std::fs::File;
//! use ages_ice_archive::{Group, IceArchive};
//!
//! let mut ice_archive = IceArchive::new(
//!     File::open("ice_file.ice").unwrap()
//! ).unwrap();
//! ice_archive.unpack_group(Group::Group1);
//! ice_archive.unpack_group(Group::Group2);
//!
//! println!("Group 1:");
//! for f in ice_archive.iter_group(Group::Group1).unwrap() {
//!     println!("\t{}", f.name().unwrap());
//! }
//!
//! println!("Group 2:");
//! for f in ice_archive.iter_group(Group::Group1).unwrap() {
//!     println!("\t{}", f.name().unwrap());
//! }
//! ```
//!
//! Writing an ICE file:
//!
//! ```
//! use std::io::Write;
//! use ages_ice_archive::{Group, IceWriter};
//! use ascii::AsciiStr;
//!
//! let mut ice_writer = IceWriter::new(4).unwrap();
//! {
//!     let mut file = ice_writer.begin_file(
//!         AsciiStr::from_ascii("hello.txt").unwrap(),
//!         AsciiStr::from_ascii("txt").unwrap(),
//!         Group::Group1,
//!     );
//!     file.write_all(b"hello world");
//!     file.finish();
//! }
//! let mut buf = Vec::new(); // any Write sink is acceptable
//! ice_writer.finish(&mut buf).unwrap();
//! ```

pub(crate) mod read;
pub(crate) mod write;

pub use self::read::{IceArchive, IceFile, GroupNotUnpacked};
pub use self::write::{IceWriter, IceFileWriter, UnsupportedVersion};

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
