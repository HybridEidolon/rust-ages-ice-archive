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

/// A loaded ICE archive.
pub struct IceArchive {
    header: IceHeader,
    group_header: IceGroupHeaders,
    data: [Vec<u8>; 2],
    encrypted: bool,
    oodle: bool,
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
pub(crate) struct IceGroupHeaders {
    pub groups: [IceGroupHeader; 2],
    pub group1_shuffled_size: U32<LE>,
    pub group2_shuffled_size: U32<LE>,
    pub key: U32<LE>,
    pub _reserved: U32<LE>,
}

impl IceGroupHeaders {
    pub fn is_compressed(&self, group: Group) -> bool {
        match group {
            Group::Group1 => self.groups[0].is_compressed(),
            Group::Group2 => self.groups[1].is_compressed(),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, FromBytes, Unaligned, AsBytes)]
#[repr(C)]
pub(crate) struct IceGroupHeader {
    pub size: U32<LE>,
    pub compressed_size: U32<LE>,
    pub file_count: U32<LE>,
    pub crc32: U32<LE>,
}

impl IceGroupHeader {
    pub fn is_compressed(&self) -> bool {
        self.compressed_size.get() != 0
    }
}

#[derive(Copy, Clone, Debug, Default, FromBytes, Unaligned, AsBytes)]
#[repr(C)]
pub(crate) struct IceInfo {
    pub r1: U32<LE>,
    pub crc32: U32<LE>,
    pub flags: U32<LE>, // 0x1 = encrypted, 0x8 = oodle codec (kraken only?), 0x40000 = vita
    pub size: U32<LE>,
}

pub(crate) static LIST13: [u32; 6] = [13, 17, 4, 7, 5, 14];
pub(crate) static LIST17: [u32; 6] = [17, 25, 15, 10, 28, 8];

#[cfg(all(feature = "oodle", any(target_os = "linux", target_os = "windows")))]
fn decompress_oodle(decompressed_size: usize, data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; decompressed_size];
    unsafe {
        let result = ooz_sys::Kraken_Decompress(data.as_ptr(), data.len(), out.as_mut_ptr(), out.len());
        if result != decompressed_size as i32 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("oodle decompression failed, result: {}", result)))
        }
    }
    Ok(out)
}

#[cfg(not(all(feature = "oodle", any(target_os = "linux", target_os = "windows"))))]
fn decompress_oodle(decompressed_size: usize, data: &[u8]) -> io::Result<Vec<u8>> {
    Err(io::Error::new(io::ErrorKind::InvalidData, "oodle decompression unsupported"))
}

fn decrypt_v3(data: &mut [u8], key: u32) {
    let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&key.to_le_bytes()).unwrap(), &Default::default());
    let size = data.len();
    blowfish.decrypt(&mut data[..(size / 8) * 8]).unwrap();
}

fn decrypt_group_v4(data: &mut [u8], version: u32, key1: u32, key2: u32) {
    let shift = if version < 5 { 16 } else { version + 5 };
    let x = ((key1 ^ (key1 >> shift)) & 0xFF) as u8;
    for b in data.iter_mut() {
        if *b != 0 && *b != x {
            *b = *b & 0xFF ^ x;
        }
    }
    let size = data.len();
    let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&key1.to_le_bytes()).unwrap(), &Default::default());
    blowfish.decrypt(&mut data[..(size / 8) * 8]).unwrap();
    if version < 5 && size <= 0x19000 || version >= 5 && size <= 0x25800 {
        let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&key2.to_le_bytes()).unwrap(), &Default::default());
        blowfish.decrypt(&mut data[..(size / 8) * 8]).unwrap();
    }
}

const VERIFY_CRC32: bool = false;

impl IceArchive {
    /// Open an IO source as an `IceArchive`, parsing the header from the start
    /// of the source and reading group data into local memory.
    pub fn load<R: Read + Seek>(mut src: R) -> io::Result<IceArchive> {
        src.seek(SeekFrom::Start(0))?;

        let mut header = [0u8; size_of::<IceHeader>()];
        src.read_exact(&mut header[..])?;
        let header = *LayoutVerified::<_, IceHeader>::new_unaligned(&header[..]).unwrap();
        header.validate()?;
        if header.version.get() > 4 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("version {} reading unsupported", header.version.get())));
        }

        let group_header: IceGroupHeaders;
        let ice_info: IceInfo;
        let mut group1_buf: Vec<u8>;
        let mut group2_buf: Vec<u8>;

        if header.version.get() == 3 {
            let mut buf = [0u8; size_of::<IceGroupHeaders>()];
            src.read_exact(&mut buf[..])?;
            group_header = *LayoutVerified::<_, IceGroupHeaders>::new_unaligned(&buf[..]).unwrap();
            let mut buf = [0u8; size_of::<IceInfo>()];
            src.read_exact(&mut buf[..])?;
            ice_info = *LayoutVerified::<_, IceInfo>::new_unaligned(&buf[..]).unwrap();

            let group1_size = if group_header.groups[0].compressed_size.get() == 0 {
                group_header.groups[0].size.get() as usize
            } else {
                group_header.groups[0].compressed_size.get() as usize
            };
            let group2_size = if group_header.groups[1].compressed_size.get() == 0 {
                group_header.groups[1].size.get() as usize
            } else {
                group_header.groups[1].compressed_size.get() as usize
            };

            // Copy groups
            src.seek(SeekFrom::Start(0x80))?;

            group1_buf = vec![0u8; group1_size];
            src.read_exact(&mut group1_buf[..])?;
            group2_buf = vec![0u8; group2_size];
            src.read_exact(&mut group2_buf[..])?;

            // Checksum group data
            let g1_checksum = crc::crc32::checksum_ieee(&group1_buf[..]);
            if VERIFY_CRC32 && g1_checksum != group_header.groups[0].crc32.get() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!(
                    "Group 1 checksum was {:08x}, expected {:08x}",
                    g1_checksum,
                    group_header.groups[0].crc32,
                )));
            }
            let g2_checksum = crc::crc32::checksum_ieee(&group2_buf[..]);
            if VERIFY_CRC32 && g2_checksum != group_header.groups[1].crc32.get() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!(
                    "Group 2 checksum was {:08x}, expected {:08x}",
                    g2_checksum,
                    group_header.groups[1].crc32,
                )));
            }

            // Global ICE Checksum
            let global_checksum = {
                use crc::Hasher32;
                let mut global_digest = crc::crc32::Digest::new_with_initial(crc::crc32::IEEE, crc::crc32::checksum_ieee(&group1_buf[..]));
                global_digest.write(&group2_buf);
                global_digest.sum32()
            };

            if ice_info.flags.get() & 0x1 != 0 {
                // Decrypt group data
                let mut key = group_header.group1_shuffled_size.get();
                if key != 0 {
                    key.swap_bytes();
                } else {
                    key = group_header.groups[0].size.get()
                        ^ group_header.groups[1].size.get()
                        ^ group_header.group2_shuffled_size.get()
                        ^ group_header.key.get()
                        ^ 0xC8D7469A;
                }

                decrypt_v3(&mut group1_buf[..], key);
                decrypt_v3(&mut group2_buf[..], key);
            }

            if VERIFY_CRC32 && global_checksum != ice_info.crc32.get() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!(
                    "ICE v3 checksum was {:08x}, expected {:08x}",
                    global_checksum,
                    ice_info.crc32.get(),
                )));
            }
        } else {
            let version = header.version.get();
            let mut buf = [0u8; size_of::<IceInfo>()];
            src.read_exact(&mut buf[..])?;
            ice_info = *LayoutVerified::<_, IceInfo>::new_unaligned(&buf[..]).unwrap();
            if version > 4 {
                src.seek(SeekFrom::Current(0x10))?;
            }
            let mut table = [0u8; 0x100];
            src.read_exact(&mut table[..])?;

            // this is encrypted if flags & 0x1
            let mut buf = [0u8; size_of::<IceGroupHeaders>()];
            src.read_exact(&mut buf[..])?;

            // eval keys anyway since the table is already there
            let key1 = get_key1(ice_info.size.get(), &table, version);
            let key2 = get_key2(key1, &table, version);
            let key3 = get_key3(key2, &table, version);
            let gh_key = key3.rotate_left(LIST13[version as usize - 4]).to_le_bytes();
            let g1_key1 = key3;
            let g1_key2 = get_key2(key3, &table, version);
            let g2_key1 = g1_key1.rotate_left(LIST17[version as usize - 4]);
            let g2_key2 = g1_key2.rotate_left(LIST17[version as usize - 4]);

            if ice_info.flags.get() & 0x1 != 0 {
                let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&gh_key[..]).unwrap(), &Default::default());
                blowfish.decrypt(&mut buf[..]).unwrap();
            }

            group_header = *LayoutVerified::<_, IceGroupHeaders>::new_unaligned(&buf[..]).unwrap();

            let group1_size = if group_header.groups[0].compressed_size.get() == 0 {
                group_header.groups[0].size.get() as usize
            } else {
                group_header.groups[0].compressed_size.get() as usize
            };
            let group2_size = if group_header.groups[1].compressed_size.get() == 0 {
                group_header.groups[1].size.get() as usize
            } else {
                group_header.groups[1].compressed_size.get() as usize
            };

            // Copy groups
            group1_buf = vec![0u8; group1_size];
            src.read_exact(&mut group1_buf[..])?;
            group2_buf = vec![0u8; group2_size];
            src.read_exact(&mut group2_buf[..])?;

            // Checksum group data
            let g1_checksum = crc::crc32::checksum_ieee(&group1_buf[..]);
            if VERIFY_CRC32 && g1_checksum != group_header.groups[0].crc32.get() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!(
                    "Group 1 checksum was {:08x}, expected {:08x}",
                    g1_checksum,
                    group_header.groups[0].crc32,
                )));
            }
            let g2_checksum = crc::crc32::checksum_ieee(&group2_buf[..]);
            if VERIFY_CRC32 && g2_checksum != group_header.groups[1].crc32.get() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!(
                    "Group 2 checksum was {:08x}, expected {:08x}",
                    g2_checksum,
                    group_header.groups[1].crc32,
                )));
            }

            if ice_info.flags.get() & 0x1 != 0 {
                // Decrypt groups
                decrypt_group_v4(&mut group1_buf[..], version, g1_key1, g1_key2);
                decrypt_group_v4(&mut group2_buf[..], version, g2_key1, g2_key2);
            }
        }

        Ok(IceArchive {
            header,
            group_header,
            data: [group1_buf, group2_buf],
            encrypted: ice_info.flags.get() & 0x1 != 0,
            oodle: ice_info.flags.get() & 0x8 != 0,
        })
    }

    /// Get the plaintext data of a Group. If the data is compressed, this slice
    /// will not already be decompressed.
    pub fn group_data(&self, group: Group) -> &[u8] {
        match group {
            Group::Group1 => &self.data[0][..],
            Group::Group2 => &self.data[1][..],
        }
    }

    /// Get the original size of a group (i.e. before compression).
    pub fn group_size(&self, group: Group) -> usize {
        match group {
            Group::Group1 => self.group_header.groups[0].size.get() as usize,
            Group::Group2 => self.group_header.groups[1].size.get() as usize,
        }
    }

    /// Get the number of files in the group.
    pub fn group_count(&self, group: Group) -> u32 {
        match group {
            Group::Group1 => self.group_header.groups[0].file_count.get(),
            Group::Group2 => self.group_header.groups[1].file_count.get(),
        }
    }

    /// Write the decompressed data from a group to a Vec<u8>. Will simply copy
    /// if the data is not compressed.
    pub fn decompress_group(&self, group: Group) -> io::Result<Vec<u8>> {
        if self.group_data(group).is_empty() {
            return Ok(Vec::new());
        }
        if !self.group_header.is_compressed(group) {
            return Ok(self.group_data(group).to_vec());
        }

        let data: Vec<u8>;
        if self.is_oodle() {
            data = decompress_oodle(self.group_size(group), self.group_data(group))?;
        } else {
            let mut d2 = Vec::with_capacity(self.group_size(group));
            ModernPrsDecoder::new(XorRead(Cursor::new(self.group_data(group)))).read_to_end(&mut d2)?;
            data = d2;
        }

        Ok(data)
    }

    /// The version of this ICE archive.
    pub fn version(&self) -> u32 {
        self.header.version.get()
    }

    /// If this ICE archive was encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// If this ICE archive is compresed with Oodle.
    pub fn is_oodle(&self) -> bool {
        self.oodle
    }

    /// If the given group is compressed.
    pub fn is_compressed(&self, group: Group) -> bool {
        self.group_header.is_compressed(group)
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

pub struct IceGroupIter<'a> {
    group: &'a [u8],
    count: u32,
    index: u32,
    offset: usize,
}

impl<'a> IceGroupIter<'a> {
    pub fn new(data: &'a [u8], count: u32) -> Result<IceGroupIter<'a>, ()> {
        let mut cursor = 0;
        for _ in 0..count {
            if data.len() < cursor + 0x40 {
                return Err(());
            }
            let file_hdr: LayoutVerified<&'a [u8], IceFileHdr> = LayoutVerified::new_unaligned(&data[cursor..cursor + 0x40]).unwrap();
            cursor += file_hdr.entry_size.get() as usize;
            if data.len() < cursor {
                return Err(());
            }
        }

        Ok(IceGroupIter {
            group: data,
            count,
            index: 0,
            offset: 0,
        })
    }
}

impl<'a> Iterator for IceGroupIter<'a> {
    type Item = IceFile<'a>;

    fn next(&mut self) -> Option<IceFile<'a>> {
        if self.index >= self.count {
            return None;
        }

        let file_hdr: LayoutVerified<&'a [u8], IceFileHdr> = LayoutVerified::new_unaligned(&self.group[self.offset..self.offset + 0x40]).unwrap();
        let next_offset = self.offset + file_hdr.entry_size.get() as usize;
        let data = &self.group[self.offset + 0x40..next_offset];
        self.offset = next_offset;
        self.index += 1;
        Some(IceFile {
            file_hdr,
            data,
        })
    }
}

struct XorRead<R: Read>(R);

impl<R: Read> Read for XorRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.0.read(buf)?;
        for b in buf[..bytes].iter_mut() {
            *b ^= 0x95;
        }
        Ok(bytes)
    }
}
