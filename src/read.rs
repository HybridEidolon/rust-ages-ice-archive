use crate::Group;

use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::mem::size_of;

use ages_prs::ModernPrsDecoder;
use ascii::AsciiStr;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::NoPadding;
use blowfish::BlowfishLE;
use blowfish::block_cipher::NewBlockCipher;
use byteorder::LittleEndian as LE;
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};
use zerocopy::byteorder::U32;

/// A loaded ICE archive whose file groups can be iterated over.
pub struct IceArchive {
    header: IceHeader,
    group_header: IceGroupHeader,
    v3_key: [u8; 4],
    group_keys: [[u32; 2]; 2],
    data: Vec<u8>,
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
}
impl ::std::fmt::Debug for IceFileHdr {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        f.debug_struct("IceFileHdr")
            .field("ext", &self.ext)
            .field("entry_size", &self.entry_size.get())
            .field("size", &self.size.get())
            .field("hdr_len", &self.hdr_len.get())
            .field("name_len", &self.name_len.get())
            .finish()
    }
}

impl<'a> IceFile<'a> {
    /// Get the ASCII file name of the file entry.
    pub fn name(&self) -> Result<&str, &'static str> {
        let name_length = self.file_hdr.name_len.get() as usize;
        AsciiStr::from_ascii(&self.data[..name_length - 1])
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
        let start = self.file_hdr.hdr_len.get() as usize - 0x40;
        let len = self.file_hdr.size.get() as usize;
        &self.data[start..len + start]
    }
}

#[derive(Clone, Copy, Debug, Default, FromBytes, Unaligned, AsBytes)]
#[repr(C)]
pub(crate) struct IceHeader {
    pub magic: [u8; 4],
    pub reserved1: U32<LE>,
    pub version: U32<LE>,
    pub reserved2: U32<LE>,
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

#[derive(Copy, Clone, Debug, Default, FromBytes, Unaligned, AsBytes)]
#[repr(C)]
pub(crate) struct IceGroupHeader {
    pub groups: [IceGroup; 2],
    pub group1_size: U32<LE>,
    pub group2_size: U32<LE>,
    pub key: U32<LE>,
    pub _reserved: U32<LE>,
}

#[derive(Copy, Clone, Debug, Default, FromBytes, Unaligned, AsBytes)]
#[repr(C)]
pub(crate) struct IceGroup {
    pub size: U32<LE>,
    pub compressed_size: U32<LE>,
    pub file_count: U32<LE>,
    pub crc32: U32<LE>,
}

#[derive(Copy, Clone, Debug, Default, FromBytes, Unaligned, AsBytes)]
#[repr(C)]
pub(crate) struct IceInfo {
    pub r1: U32<LE>,
    pub crc32: U32<LE>,
    pub r2: U32<LE>,
    pub size: U32<LE>,
}

/// Error returned by `iter_group` when the specified group has not been
/// unpacked.
#[derive(Clone, Copy, Debug)]
pub struct GroupNotUnpacked(Group);
impl ::std::fmt::Display for GroupNotUnpacked {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        fmt.write_fmt(format_args!("{} is not unpacked", self.0))
    }
}
impl ::std::error::Error for GroupNotUnpacked {}

pub(crate) static LIST13: [u32; 6] = [13, 17, 4, 7, 5, 14];
pub(crate) static LIST17: [u32; 6] = [17, 25, 15, 10, 28, 8];

impl IceArchive {
    /// Open an IO source as an `IceArchive`, parsing the header from the start
    /// of the source.
    pub fn new<R: Read + Seek>(mut src: R) -> io::Result<IceArchive> {
        src.seek(SeekFrom::Start(0))?;

        let mut header = [0u8; size_of::<IceHeader>()];
        src.read_exact(&mut header[..])?;
        let header = *LayoutVerified::<_, IceHeader>::new_unaligned(&header[..]).unwrap();
        header.validate()?;
        if header.version.get() > 4 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("version {} reading unsupported", header.version.get())));
        }

        let group_header: IceGroupHeader;
        let v3_key: [u8; 4];
        let group_keys: [[u32; 2]; 2];
        let data: Vec<u8>;
        if header.version.get() == 3 {
            let mut buf = [0u8; size_of::<IceGroupHeader>()];
            src.read_exact(&mut buf[..])?;
            group_header = *LayoutVerified::<_, IceGroupHeader>::new_unaligned(&buf[..]).unwrap();
            let mut buf = [0u8; size_of::<IceInfo>()];
            src.read_exact(&mut buf[..])?;
            let ice_info = *LayoutVerified::<_, IceInfo>::new_unaligned(&buf[..]).unwrap();

            let mut key = group_header.group1_size.get();
            if key != 0 {
                key.swap_bytes();
            } else {
                key = group_header.groups[0].size.get() ^ group_header.groups[1].size.get() ^ group_header.group2_size.get() ^ group_header.key.get() ^ 0xC8D7469A;
            }
            src.seek(SeekFrom::Start(0x80))?;
            let mut data_buf = Vec::with_capacity(std::cmp::min(ice_info.size.get() as usize, 4 * 1024 * 1024));
            src.read_to_end(&mut data_buf)?;
            let read_checksum = crc::crc32::checksum_ieee(&data_buf[..]);
            if read_checksum != ice_info.crc32.get() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "ice archive v3 crc32 check failed"));
            }

            v3_key = key.to_le_bytes();
            group_keys = Default::default();
            data = data_buf;
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
            let gh_key = key3.rotate_left(LIST13[version as usize - 4]).to_le_bytes();
            let g1_key1 = key3;
            let g1_key2 = get_key2(key3, &table, version);
            let g2_key1 = g1_key1.rotate_left(LIST17[version as usize - 4]);
            let g2_key2 = g1_key2.rotate_left(LIST17[version as usize - 4]);

            let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&gh_key[..]).unwrap(), &Default::default());
            blowfish.decrypt(&mut buf[..]).unwrap();
            group_header = *LayoutVerified::<_, IceGroupHeader>::new_unaligned(&buf[..]).unwrap();

            // read in the data for checksum validation + cache
            let mut g1_offset = 16 + 16 + 0x100 + 48;
            if version > 4 {
                g1_offset += 10;
            }
            src.seek(SeekFrom::Start(g1_offset))?;
            let mut data_buf = Vec::with_capacity(std::cmp::min(info.size.get() as usize, 4 * 1024 * 1024));
            src.read_to_end(&mut data_buf)?;
            let _read_checksum = crc::crc32::checksum_ieee(&data_buf[..]);
            // TODO do checksum by decrypting ahead and only decompressing when unpacking
            // if read_checksum != info.crc32.get() {
            //     return Err(io::Error::new(io::ErrorKind::InvalidInput, "ice archive v4+ crc32 check failed"));
            // }

            data = data_buf;
            v3_key = Default::default();
            group_keys = [
                [g1_key1, g1_key2],
                [g2_key1, g2_key2],
            ];
        }

        Ok(IceArchive {
            header,
            group_header,
            v3_key,
            group_keys,
            data,
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
        let g1_size = match group {
            Group::Group1 => enc_buf_size,
            Group::Group2 => if self.group_header.groups[0].compressed_size.get() != 0 {
                self.group_header.groups[0].compressed_size.get() as usize
            } else {
                self.group_header.groups[0].size.get() as usize
            }
        };
        let group_data_size = if compressed {
            group_data.compressed_size.get() as usize
        } else {
            group_data.size.get() as usize
        };

        if group_data_size == 0 {
            self.dec[group_index] = Some(Vec::new());
            if self.is_group_unpacked(Group::Group1) && self.is_group_unpacked(Group::Group2) {
                self.data = Vec::new(); // deallocate since it's no longer needed
            }
            return Ok(());
        }

        let group_slice_start: usize;
        let group_slice_end: usize;
        let group_slice_len: usize;
        if group == Group::Group1 {
            group_slice_start = 0;
        } else {
            group_slice_start = g1_size as usize;
        }
        group_slice_end = group_slice_start + group_data_size as usize;
        group_slice_len = group_slice_end - group_slice_start;

        // verify checksum
        let read_checksum = crc::crc32::checksum_ieee(&self.data[group_slice_start..group_slice_end]);
        if read_checksum != group_data.crc32.get() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid group data checksum"));
        }

        if self.header.version.get() == 3 {
            let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&self.v3_key).unwrap(), &Default::default());
            blowfish.decrypt(&mut self.data[group_slice_start..(group_slice_end - group_slice_len % 8)]).unwrap();
            if compressed {
                let mut decompressed = Vec::with_capacity(group_data.size.get() as usize);
                for b in self.data[group_slice_start..group_slice_end].iter_mut() {
                    *b ^= 0x95;
                }

                {
                    ModernPrsDecoder::new(Cursor::new(&self.data[group_slice_start..group_slice_end])).read_to_end(&mut decompressed)?;
                }

                self.dec[group_index] = Some(decompressed);
                if self.is_group_unpacked(Group::Group1) && self.is_group_unpacked(Group::Group2) {
                    self.data = Vec::new(); // deallocate since it's no longer needed
                }
                return Ok(());
            } else {
                self.dec[group_index] = Some(Vec::from(&self.data[group_slice_start..group_slice_end]));
                if self.is_group_unpacked(Group::Group1) && self.is_group_unpacked(Group::Group2) {
                    self.data = Vec::new(); // deallocate since it's no longer needed
                }
                return Ok(());
            }
        } else {
            let gk = self.group_keys[group_index];

            let shift = if self.version() < 5 { 16 } else { self.version() + 5 };
            let x = ((gk[0] ^ (gk[0] >> shift)) & 0xFF) as u8;
            for b in self.data[group_slice_start..group_slice_end].iter_mut() {
                if *b != 0 && *b != x {
                    *b = *b & 0xFF ^ x;
                }
            }
            let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&gk[0].to_le_bytes()).unwrap(), &Default::default());
            blowfish.decrypt(&mut self.data[group_slice_start..(group_slice_end - group_slice_len % 8)]).unwrap();

            let size = group_data.compressed_size.get();
            if self.version() < 5 && size <= 0x19000 || self.version() >= 5 && size <= 0x25800 {
                let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&gk[1].to_le_bytes()).unwrap(), &Default::default());
                blowfish.decrypt(&mut self.data[group_slice_start..(group_slice_end - group_slice_len % 8)]).unwrap();
            }

            if compressed {
                let mut decompressed = Vec::with_capacity(group_data.size.get() as usize);
                for b in self.data[group_slice_start..group_slice_end].iter_mut() {
                    *b ^= 0x95;
                }
                {
                    ModernPrsDecoder::new(Cursor::new(&self.data[group_slice_start..group_slice_end])).read_to_end(&mut decompressed)?;
                }
                self.dec[group_index] = Some(decompressed);
                if self.is_group_unpacked(Group::Group1) && self.is_group_unpacked(Group::Group2) {
                    self.data = Vec::new(); // deallocate since it's no longer needed
                }
                return Ok(());
            } else {
                self.dec[group_index] = Some(Vec::from(&self.data[group_slice_start..group_slice_end]));
                if self.is_group_unpacked(Group::Group1) && self.is_group_unpacked(Group::Group2) {
                    self.data = Vec::new(); // deallocate since it's no longer needed
                }
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

    /// The version of this ICE archive.
    pub fn version(&self) -> u32 {
        self.header.version.get()
    }

    /// Get an iterator over the files in a group, if the group is unpacked.
    ///
    /// Call `unpack_group` before using.
    pub fn iter_group<'a>(&'a self, group: Group) -> Result<impl Iterator<Item=IceFile<'a>>, GroupNotUnpacked> {
        if !self.is_group_unpacked(group) {
            return Err(GroupNotUnpacked(group));
        }

        Ok(IceGroupIter {
            archive: self,
            group,
            index: 0,
            dec_offset: 0,
        })
    }
}

pub(crate) fn get_key1(size: u32, table: &[u8; 0x100], version: u32) -> u32 {
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

pub(crate) fn get_key2(key: u32, table: &[u8; 0x100], version: u32) -> u32 {
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

pub(crate) fn get_key3(mut key: u32, table: &[u8; 0x100], version: u32) -> u32 {
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

struct IceGroupIter<'a> {
    archive: &'a IceArchive,
    group: Group,
    index: usize,
    dec_offset: usize,
}

impl<'a> Iterator for IceGroupIter<'a> {
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

        let file_hdr: LayoutVerified<&'a [u8], IceFileHdr> = LayoutVerified::new_unaligned(&self.archive.dec[group_index].as_ref().unwrap()[self.dec_offset..self.dec_offset + 0x40]).unwrap();
        let next_offset = self.dec_offset + file_hdr.entry_size.get() as usize;
        let data: &'a [u8] = &self.archive.dec[group_index].as_ref().unwrap()[self.dec_offset + 0x40..next_offset];
        self.dec_offset = next_offset;
        self.index += 1;
        Some(IceFile {
            file_hdr,
            data,
        })
    }
}
