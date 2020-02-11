//! Operations over SEGA ICE archives, used in _Phantasy Star Online 2_.

use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::mem::size_of;

use ages_prs::ModernPrsDecoder;
use ascii::AsciiStr;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::NoPadding;
use blowfish::BlowfishLE;
use blowfish::block_cipher::NewBlockCipher;
use byteorder::LittleEndian as LE;
use zerocopy::{FromBytes, LayoutVerified, Unaligned};
use zerocopy::byteorder::U32;

/// A loaded ICE archive whose file groups can be iterated over.
pub struct IceArchive<R> {
    src: R,
    header: IceHeader,
    group_header: IceGroupHeader,
    v3_key: [u8; 4],
    group_keys: [[u32; 2]; 2],
    dec: [Option<Vec<u8>>; 2],
}

/// A handle to an ICE Archive's file entry.
pub struct IceFile<'a> {
    file_hdr: LayoutVerified<&'a [u8], IceFileHdr>,
    data: &'a [u8],
}

#[derive(Copy, Clone, FromBytes, Unaligned)]
#[repr(C)]
struct IceFileHdr {
    ext: [u8; 4],
    entry_size: U32<LE>,
    size: U32<LE>,
    hdr_len: U32<LE>,
    name_len: U32<LE>,
    _reserved: [u8; 44],
    name: [u8; 32],
}

impl<'a> IceFile<'a> {
    /// Get the ASCII file name of the file entry.
    pub fn name(&self) -> Result<&str, &'static str> {
        let name_length = self.file_hdr.name_len.get() as usize;
        AsciiStr::from_ascii(&self.file_hdr.name[..name_length - 1])
            .map(|v| v.as_str())
            .map_err(|_| "non-ascii file name in ice file")
    }

    /// Get the reported ASCII extension of the file entry.
    pub fn ext(&self) -> Result<&str, &'static str> {
        let ext_length = {
            let mut len = 4;
            for i in 0..4 {
                if self.file_hdr.ext[i] == 0 {
                    len = i;
                    break;
                }
            }
            len
        };
        AsciiStr::from_ascii(&self.file_hdr.ext[..ext_length])
            .map(|v| v.as_str())
            .map_err(|_| "non-ascii extension in ice file")
    }

    /// Get a slice of the file data.
    pub fn data(&self) -> &[u8] {
        let len = self.file_hdr.size.get() as usize;
        &self.data[..len]
    }
}

#[derive(Clone, Copy, Debug, FromBytes, Unaligned)]
#[repr(C)]
struct IceHeader {
    magic: [u8; 4],
    reserved1: U32<LE>,
    version: U32<LE>,
    reserved2: U32<LE>,
}

impl IceHeader {
    fn validate(&self) -> io::Result<()> {
        if self.magic != b"ICE\0"[..] {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid ICE magic"));
        }
        if self.reserved1.get() != 0 || self.reserved2.get() != 0x80 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid ICE header reserved values"));
        }
        let version = self.version.get();
        if !(3..=9).contains(&version) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid ICE version"));
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, FromBytes, Unaligned)]
#[repr(C)]
struct IceGroupHeader {
    groups: [IceGroup; 2],
    group1_size: U32<LE>,
    group2_size: U32<LE>,
    key: U32<LE>,
    _reserved: U32<LE>,
}

#[derive(Copy, Clone, Debug, FromBytes, Unaligned)]
#[repr(C)]
struct IceGroup {
    size: U32<LE>,
    compressed_size: U32<LE>,
    file_count: U32<LE>,
    crc32: U32<LE>,
}

#[derive(Copy, Clone, Debug, FromBytes, Unaligned)]
#[repr(C)]
struct IceInfo {
    r1: U32<LE>,
    crc32: U32<LE>,
    r2: U32<LE>,
    size: U32<LE>,
}

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

/// Error returned by `iter_group` when the specified group has not been
/// unpacked.
#[derive(Clone, Copy, Debug)]
pub struct GroupNotUnpackedError(Group);
impl ::std::fmt::Display for GroupNotUnpackedError {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        fmt.write_fmt(format_args!("{} is not unpacked", self.0))
    }
}
impl ::std::error::Error for GroupNotUnpackedError {}

impl<R: Read + Seek> IceArchive<R> {
    /// Open an IO source as an `IceArchive`, parsing the header from the start
    /// of the source.
    pub fn new(mut src: R) -> io::Result<IceArchive<R>> {
        src.seek(SeekFrom::Start(0))?;

        let mut header = [0u8; size_of::<IceHeader>()];
        src.read_exact(&mut header[..])?;
        let header = *LayoutVerified::<_, IceHeader>::new_unaligned(&header[..]).unwrap();
        header.validate()?;

        let group_header: IceGroupHeader;
        let v3_key: [u8; 4];
        let group_keys: [[u32; 2]; 2];
        if header.version.get() == 3 {
            let mut buf = [0u8; size_of::<IceGroupHeader>()];
            src.read_exact(&mut buf[..])?;
            group_header = *LayoutVerified::<_, IceGroupHeader>::new_unaligned(&buf[..]).unwrap();
            let mut buf = [0u8; size_of::<IceInfo>()];
            src.read_exact(&mut buf[..])?;

            let mut key = group_header.group1_size.get();
            if key != 0 {
                key.swap_bytes();
            } else {
                key = group_header.groups[0].size.get() ^ group_header.groups[1].size.get() ^ group_header.group2_size.get() ^ group_header.key.get() ^ 0xC8D7469A;
            }

            v3_key = key.to_le_bytes();
            group_keys = Default::default();
        } else {
            let version = header.version.get();
            let mut buf = [0u8; size_of::<IceInfo>()];
            src.read_exact(&mut buf[..])?;
            let info = *LayoutVerified::<_, IceInfo>::new_unaligned(&buf[..]).unwrap();
            if version > 4 {
                src.seek(SeekFrom::Current(10))?;
            }
            let mut table = [0u8; 0x100];
            src.read_exact(&mut table[..])?;

            // this is encrypted
            let mut buf = [0u8; size_of::<IceGroupHeader>()];
            src.read_exact(&mut buf[..])?;

            let key1 = get_key1(info.size.get(), &table, version);
            let key2 = get_key2(key1, &table, version);
            let key3 = get_key3(key2, &table, version);

            static LIST13: [u32; 6] = [13, 17, 4, 7, 5, 14];
            static LIST17: [u32; 6] = [17, 25, 15, 10, 28, 8];
            let gh_key = key3.rotate_left(LIST13[version as usize - 4]).to_le_bytes();
            let g1_key1 = key3;
            let g1_key2 = get_key2(key3, &table, version);
            let g2_key1 = g1_key1.rotate_left(LIST17[version as usize - 4]);
            let g2_key2 = g1_key2.rotate_left(LIST17[version as usize - 4]);

            let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&gh_key[..]).unwrap(), &Default::default());
            blowfish.decrypt(&mut buf[..]).unwrap();
            group_header = *LayoutVerified::<_, IceGroupHeader>::new_unaligned(&buf[..]).unwrap();
            v3_key = Default::default();
            group_keys = [
                [g1_key1, g1_key2],
                [g2_key1, g2_key2],
            ];
        }

        Ok(IceArchive {
            src,
            header,
            group_header,
            v3_key,
            group_keys,
            dec: [None, None]
        })
    }

    /// Unpack a group from the source, caching the decompressed data, for
    /// further indexing.
    ///
    /// Does nothing if the group is already unpacked.
    pub fn unpack_group(&mut self, group: Group) -> io::Result<()> {
        if self.is_group_unpacked(group) {
            return Ok(());
        }
        let group_index = match group {
            Group::Group1 => 0,
            Group::Group2 => 1,
        };
        let group_data: IceGroup = self.group_header.groups[group_index];
        let enc_buf_size;
        let compressed = group_data.compressed_size.get() != 0;
        if compressed {
            enc_buf_size = group_data.compressed_size.get() as usize;
        } else {
            enc_buf_size = group_data.size.get() as usize;
        }

        if self.header.version.get() == 3 {
            // easy; use the key we have to blowfish decrypt, then decompress
            if group == Group::Group1 {
                self.src.seek(SeekFrom::Start(0x80))?;
            } else {
                self.src.seek(SeekFrom::Start(0x80 + enc_buf_size as u64))?;
            }

            let mut enc_buf = Vec::with_capacity(enc_buf_size);
            enc_buf.resize(enc_buf_size, 0);
            self.src.read_exact(&mut enc_buf[..])?;
            let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&self.v3_key).unwrap(), &Default::default());
            blowfish.decrypt(&mut enc_buf[..(enc_buf_size - enc_buf_size % 8)]).unwrap();
            if compressed {
                let mut decompressed = Vec::with_capacity(group_data.size.get() as usize);
                for b in enc_buf.iter_mut() {
                    *b ^= 0x95;
                }
                ModernPrsDecoder::new(Cursor::new(enc_buf)).read_to_end(&mut decompressed)?;
                self.dec[group_index] = Some(decompressed);
                return Ok(());
            } else {
                self.dec[group_index] = Some(enc_buf);
                return Ok(());
            }
        } else {
            let mut g1_offset = 16 + 16 + 0x100 + 48;
            if self.version() > 4 {
                g1_offset += 10;
            }
            if group == Group::Group1 {
                self.src.seek(SeekFrom::Start(g1_offset))?;
            } else {
                self.src.seek(SeekFrom::Start(g1_offset + enc_buf_size as u64))?;
            }

            let mut enc_buf = Vec::with_capacity(enc_buf_size);
            enc_buf.resize(enc_buf_size, 0);
            self.src.read_exact(&mut enc_buf[..])?;

            let gk = self.group_keys[group_index];

            let shift = if self.version() < 5 { 16 } else { self.version() + 5 };
            let x = ((gk[0] ^ (gk[0] >> shift)) & 0xFF) as u8;
            for b in enc_buf.iter_mut() {
                if *b != 0 && *b != x {
                    *b = *b & 0xFF ^ x;
                }
            }
            let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&gk[0].to_le_bytes()).unwrap(), &Default::default());
            blowfish.decrypt(&mut enc_buf[..(enc_buf_size - enc_buf_size % 8)]).unwrap();

            let size = group_data.compressed_size.get();
            if self.version() < 5 && size <= 0x19000 || self.version() >= 5 && size <= 0x25800 {
                let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&gk[1].to_le_bytes()).unwrap(), &Default::default());
                blowfish.decrypt(&mut enc_buf[..(enc_buf_size - enc_buf_size % 8)]).unwrap();
            }

            if compressed {
                let mut decompressed = Vec::with_capacity(group_data.size.get() as usize);
                for b in enc_buf.iter_mut() {
                    *b ^= 0x95;
                }
                ModernPrsDecoder::new(Cursor::new(enc_buf)).read_to_end(&mut decompressed)?;
                self.dec[group_index] = Some(decompressed);
                return Ok(());
            } else {
                self.dec[group_index] = Some(enc_buf);
                return Ok(());
            }
        }
    }

    /// `true` if the given group is already unpacked (i.e., can be indexed).
    pub fn is_group_unpacked(&self, group: Group) -> bool {
        match group {
            Group::Group1 => self.dec[0].is_some(),
            Group::Group2 => self.dec[1].is_some(),
        }
    }

    /// Unwrap this `IceArchive` into the inner IO source.
    pub fn into_inner(self) -> R {
        self.src
    }

    /// The version of this ICE archive.
    pub fn version(&self) -> u32 {
        self.header.version.get()
    }

    /// Get an iterator over the files in a group, if the group is unpacked.
    ///
    /// Call `unpack_group` before using.
    pub fn iter_group<'a>(&'a self, group: Group) -> Result<impl Iterator<Item=IceFile<'a>>, GroupNotUnpackedError> {
        if !self.is_group_unpacked(group) {
            return Err(GroupNotUnpackedError(group));
        }

        Ok(IceGroupIter {
            archive: self,
            group,
            index: 0,
            dec_offset: 0,
        })
    }
}

fn get_key1(size: u32, table: &[u8; 0x100], version: u32) -> u32 {
    assert!((4..=9).contains(&version));
    static LIST: [u32; 18] = [
        0x6C, 0x7C, 0xDC, 0x83, 0x0A, 0xD2, 0xB3, 0x50, 0x61,
        0xD7, 0x17, 0x47, 0x16, 0x54, 0x61, 0xDC, 0xBD, 0xDB,
    ];
    let version = version as usize;
    let a = LIST[(version - 4) * 3 + 0] as usize;
    let b = LIST[(version - 4) * 3 + 1] as usize;
    let c = LIST[(version - 4) * 3 + 2] as usize;
    let base = u32::from_le_bytes([table[a + 0], table[a + 1], table[a + 2], table[a + 3]]);
    let cs = crc::crc32::checksum_ieee(&table[b..c]);
    ((base ^ size) ^ cs) ^ 0x4352F5C2
}

fn get_key2(key: u32, table: &[u8; 0x100], version: u32) -> u32 {
    assert!((4..=9).contains(&version));
    let a;
    let b;
    if version == 4 {
        b = [8, 24, 0, 16];
    } else {
        b = [16, 8, 24, 0];
    }
    let version = version as usize;
    static LIST: [u32; 24] = [
        0x5D, 0x3F, 0x45, -0x3Ai32 as u32, 0xE2, 0xC6, 0xA1, 0xF3, 0xE8, 0xAE, 0xB7, 0x64,
        0x08, 0xF9, 0x5D, 0xFD,  0xC8, 0xAA, 0x5E, 0x7A, 0x0D, 0x9C, 0xF5, 0x93,
    ];
    a = [
        LIST[(version - 4) * 4 + 0] as usize,
        LIST[(version - 4) * 4 + 1] as usize,
        LIST[(version - 4) * 4 + 2] as usize,
        LIST[(version - 4) * 4 + 3] as usize,
    ];
    let p: [u32; 4] = [
        ((table[((key >> 0) as usize + a[0]) & 0xFF]).rotate_left(a[0] as u32 & 7) as u32) << b[0],
        ((table[((key >> 8) as usize + a[1]) & 0xFF]).rotate_left(a[1] as u32 & 7) as u32) << b[1],
        ((table[((key >> 16) as usize + a[2]) & 0xFF]).rotate_left(a[2] as u32 & 7) as u32) << b[2],
        ((table[((key >> 24) as usize + a[3]) & 0xFF]).rotate_left(a[3] as u32 & 7) as u32) << b[3],
    ];
    p[0] | p[1] | p[2] | p[3]
}

fn get_key3(mut key: u32, table: &[u8; 0x100], version: u32) -> u32 {
    static KEY1: u32 = 0x4352F5C2;
    assert!((4..=9).contains(&version));
    if version < 5 {
        key ^= KEY1 ^ 0xCD50379E;
        let mut count = ((0x24924925u64 * key as u64) >> 32) as u32;
        count = key - ((((key - count) >> 1) + count) >> 2) * 7 + 2;
        let count = count as usize;
        for _ in 0..count {
            key = get_key2(key, table, version);
        }
    } else {
        key ^= KEY1 ^ 0xCD50379E;
        let mut count = ((0x4EC4EC4Fu64 * key as u64) >> 32) as u32;
        count = key - (count >> 2) * 13 + 3;
        let count = count as usize;
        for _ in 0..count {
            key = get_key2(key, table, version);
        }
    }

    KEY1 ^ 0xCD50379E ^ key
}

struct IceGroupIter<'a, R> {
    archive: &'a IceArchive<R>,
    group: Group,
    index: usize,
    dec_offset: usize,
}

impl<'a, R: Read + Seek> Iterator for IceGroupIter<'a, R> {
    type Item = IceFile<'a>;

    fn next(&mut self) -> Option<IceFile<'a>> {
        if !self.archive.is_group_unpacked(self.group) {
            return None;
        }
        let group_index = match self.group {
            Group::Group1 => 0,
            Group::Group2 => 1,
        };
        let file_count = self.archive.group_header.groups[group_index].file_count.get() as usize;
        if self.index >= file_count {
            return None;
        }

        let file_hdr: LayoutVerified<&'a [u8], IceFileHdr> = LayoutVerified::new_unaligned(&self.archive.dec[group_index].as_ref().unwrap()[self.dec_offset..self.dec_offset + 0x60]).unwrap();
        let next_offset = self.dec_offset + file_hdr.entry_size.get() as usize;
        let data: &'a [u8] = &self.archive.dec[group_index].as_ref().unwrap()[self.dec_offset + 0x50..next_offset];
        self.dec_offset = next_offset;
        self.index += 1;
        Some(IceFile {
            file_hdr,
            data,
        })
    }
}
