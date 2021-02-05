use crate::Group;

use std::io::{self, Write};

use ages_prs::ModernPrsEncoder;
use ascii::{AsciiStr, AsciiString};
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::NoPadding;
use blowfish::BlowfishLE;
use blowfish::block_cipher::NewBlockCipher;
use byteorder::{LittleEndian as LE, WriteBytesExt};
use rand::Rng;
use zerocopy::AsBytes;

/// Type for writing an ICE archive.
pub struct IceWriter {
    files: [Vec<FileEntry>; 2],
    version: u32,
    compress: bool,
    encrypt: bool,
    oodle: bool,
}

struct FileEntry {
    ext: AsciiString,
    name: AsciiString,
    buf: Vec<u8>,
}

impl FileEntry {
    fn write_file<W: Write>(&self, mut out: W) -> io::Result<usize> {
        let mut padding_bytes = 16 - self.buf.len() % 16;
        if padding_bytes == 16 { padding_bytes = 0; }

        out.write_all(self.ext.as_bytes())?;
        if self.ext.len() % 4 != 0 {
            for _ in std::iter::repeat(0).take(4 - self.ext.len() % 4) {
                out.write_u8(0)?;
            }
        }
        let name_length = self.name.len() + 1;
        let name_length_padded = name_length + (16 - name_length % 16);
        let padded_size = self.buf.len() + padding_bytes + 0x40 + name_length_padded;
        out.write_u32::<LE>(padded_size as u32)?;
        out.write_u32::<LE>(self.buf.len() as u32)?;
        out.write_u32::<LE>(0x40 + name_length_padded as u32)?;
        out.write_u32::<LE>(name_length as u32)?;
        for _ in std::iter::repeat(0).take(44) {
            out.write_u8(0)?;
        }
        out.write_all(self.name.as_bytes())?;
        for _ in std::iter::repeat(0).take(name_length_padded - self.name.len()) {
            out.write_u8(0)?;
        }
        out.write_all(&self.buf[..])?;
        for _ in std::iter::repeat(0).take(padding_bytes) {
            out.write_u8(0)?;
        }
        Ok(padded_size)
    }
}

/// Error indicating that the provided ICE version is unsupported by this
/// implementation.
#[derive(Clone, Copy, Debug)]
pub struct UnsupportedVersion(u32);
impl ::std::fmt::Display for UnsupportedVersion {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        f.write_fmt(format_args!("Unsupported ICE version {}", self.0))
    }
}
impl ::std::error::Error for UnsupportedVersion {}


#[cfg(all(feature = "oodle", any(target_os = "linux", target_os = "windows")))]
fn compress_oodle(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; data.len() + 4096];
    unsafe {
        let result = ooz_sys::Compress(
            ooz_sys::Compressor::Kraken,
            data.as_ptr(),
            out.as_mut_ptr(),
            data.len() as i32,
            ooz_sys::CompressorLevel::Normal,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        if result <= 0 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("oodle compression failed; ooz result {}", result)));
        }
        out.truncate(result as usize);
    }
    Ok(out)
}

#[cfg(not(all(feature = "oodle", any(target_os = "linux", target_os = "windows"))))]
fn compress_oodle(data: &[u8]) -> io::Result<Vec<u8>> {
    Err(io::Error::new(io::ErrorKind::InvalidData, "oodle compression unsupported"))
}

impl IceWriter {
    /// Begin a new ICE archive.
    pub fn new(version: u32, compress: bool, encrypt: bool, oodle: bool) -> Result<IceWriter, UnsupportedVersion> {
        if !(3..=4).contains(&version) {
            return Err(UnsupportedVersion(version));
        }

        Ok(IceWriter {
            version,
            compress,
            encrypt,
            oodle,
            files: Default::default(),
        })
    }

    /// Begin a file.
    ///
    /// The `finish` method must be called on the file writer to add the file to
    /// the archive.
    pub fn begin_file<'a>(&'a mut self, name: &AsciiStr, ext: &AsciiStr, group: Group) -> IceFileWriter<'a> {
        IceFileWriter {
            writer: self,
            name: name.to_owned(),
            ext: ext.to_owned(),
            group,
            buf: Vec::with_capacity(1024),
        }
    }

    /// Write the composed ICE archive into the given sink.
    pub fn finish<W: Write>(&self, mut sink: W) -> io::Result<()> {
        assert!((3..=9).contains(&self.version));

        let filecount1 = self.files[0].len();
        let filecount2 = self.files[1].len();

        let summed_g1 = self.files[0].iter().map(|f| f.buf.len() + 0x50).sum();
        let summed_g2 = self.files[1].iter().map(|f| f.buf.len() + 0x50).sum();

        let mut g1 = Vec::with_capacity(summed_g1);
        let mut g2 = Vec::with_capacity(summed_g2);

        for f in self.files[0].iter() {
            f.write_file(&mut g1)?;
        }

        for f in self.files[1].iter() {
            f.write_file(&mut g2)?;
        }

        let mut comp1: Vec<u8>;
        let mut comp2: Vec<u8>;

        let mut uncompressed_size1 = g1.len();
        let compressed_size1;
        let mut uncompressed_size2 = g2.len();
        let compressed_size2;

        if self.compress {
            let comp1_len: usize;
            let comp2_len: usize;
            if self.oodle {
                if g1.len() > 0 {
                    let ncomp1 = compress_oodle(&g1[..])?;
                    comp1_len = ncomp1.len();
                    comp1 = ncomp1;
                } else {
                    comp1_len = 0;
                    comp1 = Vec::new();
                }
                if g2.len() > 0 {
                    let ncomp2 = compress_oodle(&g2[..])?;
                    comp2_len = ncomp2.len();
                    comp2 = ncomp2;
                } else {
                    comp2_len = 0;
                    comp2 = Vec::new();
                }
            } else {
                let mut ncomp1 = Vec::with_capacity(g1.len() / 2);
                let mut ncomp2 = Vec::with_capacity(g2.len() / 2);
                if g1.len() > 0 {
                    ModernPrsEncoder::new(&mut ncomp1).write_all(&g1[..])?;
                }
                if g2.len() > 0 {
                    ModernPrsEncoder::new(&mut ncomp2).write_all(&g2[..])?;
                }
                for b in ncomp1.iter_mut().chain(ncomp2.iter_mut()) {
                    *b ^= 0x95;
                }
                comp1_len = ncomp1.len();
                comp1 = ncomp1;
                comp2_len = ncomp2.len();
                comp2 = ncomp2;
            }

            let comp1_padded_size = if comp1_len / 16 == 0 { comp1_len } else { comp1_len + comp1_len % 16 };
            let comp2_padded_size = if comp2_len / 16 == 0 { comp2_len } else { comp2_len + comp2_len % 16 };

            comp1.resize(comp1_padded_size, 0);
            comp2.resize(comp2_padded_size, 0);
            compressed_size1 = comp1_padded_size;
            compressed_size2 = comp2_padded_size;
        } else {
            // uncompressed
            compressed_size1 = 0;
            compressed_size2 = 0;

            let comp1_padded_size = if g1.len() / 16 == 0 { g1.len() } else { g1.len() + g1.len() % 16 };
            let comp2_padded_size = if g2.len() / 16 == 0 { g2.len() } else { g2.len() + g2.len() % 16 };

            comp1 = g1;
            comp2 = g2;
            comp1.resize(comp1_padded_size, 0);
            comp2.resize(comp2_padded_size, 0);
            uncompressed_size1 = comp1.len();
            uncompressed_size2 = comp2.len();
        }

        // encryption is based on chosen version
        if self.version == 3 {
            // v3 encryption
            // use 1 key for both groups
            // header is unencrypted
            let source_key: u32 = rand::random();

            let key = uncompressed_size1 as u32 ^ uncompressed_size2 as u32 ^ 0u32 ^ source_key ^ 0xC8D7469Au32;

            if self.encrypt {
                let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&key.to_le_bytes()[..]).unwrap(), &Default::default());
                blowfish.encrypt(&mut comp1[..(compressed_size1 / 8) * 8], compressed_size1 / 8 * 8).unwrap();
                let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&key.to_le_bytes()[..]).unwrap(), &Default::default());
                blowfish.encrypt(&mut comp2[..(compressed_size2 / 8) * 8], compressed_size2 / 8 * 8).unwrap();
            }

            let crcg1 = if comp1.len() > 0 { crc::crc32::checksum_ieee(&comp1[..]) } else { 0 };
            let crcg2 = if comp2.len() > 0 { crc::crc32::checksum_ieee(&comp2[..]) } else { 0 };

            let mut header = crate::read::IceHeader::default();
            header.magic[..].copy_from_slice(b"ICE\0");
            header.reserved1.set(0);
            header.version.set(self.version);
            header.reserved2.set(0x80);

            let mut gh = crate::read::IceGroupHeader::default();
            gh.groups[0].size.set(uncompressed_size1 as u32);
            gh.groups[0].compressed_size.set(compressed_size1 as u32);
            gh.groups[0].file_count.set(filecount1 as u32);
            gh.groups[0].crc32.set(crcg1);
            gh.groups[1].size.set(uncompressed_size2 as u32);
            gh.groups[1].compressed_size.set(compressed_size2 as u32);
            gh.groups[1].file_count.set(filecount2 as u32);
            gh.groups[1].crc32.set(crcg2);
            // gh.group1_size.set(compressed_size1 as u32);
            // gh.group2_size.set(compressed_size2 as u32);
            gh.key.set(source_key);

            // write IceInfo
            let mut info = crate::read::IceInfo::default();
            info.r1.set(0xFF);
            let mut flags: u32= 0;
            if self.encrypt {
                flags |= 0x1;
            }
            if self.oodle {
                flags |= 0x8;
            }
            info.flags.set(flags);
            info.size.set((
                std::mem::size_of::<crate::read::IceHeader>()
                + std::mem::size_of::<crate::read::IceInfo>()
                + 0x100
                + std::mem::size_of::<crate::read::IceGroupHeader>()
                + compressed_size1
                + compressed_size2
            ) as u32);
            // evaluate CRC32 of the archive
            let crc = {
                use crc::Hasher32;
                let mut c = crc::crc32::Digest::new_with_initial(crc::crc32::IEEE, crc::crc32::checksum_ieee(&comp1[..]));
                c.write(&comp2[..]);
                c.sum32()
            };
            info.crc32.set(crc);

            sink.write_all(header.as_bytes())?;
            sink.write_all(gh.as_bytes())?;
            sink.write_all(info.as_bytes())?;
            sink.write_all(&[0u8; 0x30])?;
            sink.write_all(&comp1[..])?;
            sink.write_all(&comp2[..])?;

            Ok(())
        } else {
            // v4-9 encryption

            // write IceHeader
            let mut header = crate::read::IceHeader::default();
            header.magic[..].copy_from_slice(b"ICE\0");
            header.reserved1.set(0);
            header.version.set(self.version);
            header.reserved2.set(0x80);

            let mut info = crate::read::IceInfo::default();
            info.r1.set(0xFF);
            let mut flags: u32= 0;
            if self.encrypt {
                flags |= 0x1;
            }
            if self.oodle {
                flags |= 0x8;
            }
            info.flags.set(flags);
            info.size.set((
                std::mem::size_of::<crate::read::IceHeader>()
                + std::mem::size_of::<crate::read::IceInfo>()
                + 0x100
                + std::mem::size_of::<crate::read::IceGroupHeader>()
                + compressed_size1
                + compressed_size2
                + if self.version > 4 { 0x10 } else { 0 }
            ) as u32);

            let mut table: [u8; 0x100] = [0; 0x100];
            if self.encrypt {
                rand::thread_rng().fill(&mut table[..]);
            }


            // generate keys
            let key1 = crate::read::get_key1(info.size.get(), &table, self.version);
            let key2 = crate::read::get_key2(key1, &table, self.version);
            let key3 = crate::read::get_key3(key2, &table, self.version);
            let gh_key = key3.rotate_left(crate::read::LIST13[self.version as usize - 4]).to_le_bytes();
            let g1_key1 = key3;
            let g1_key2 = crate::read::get_key2(key3, &table, self.version);
            let g2_key1 = g1_key1.rotate_left(crate::read::LIST17[self.version as usize - 4]);
            let g2_key2 = g1_key2.rotate_left(crate::read::LIST17[self.version as usize - 4]);

            // crc in v4-9 is BEFORE encryption
            let crc = {
                use crc::Hasher32;
                let mut c = crc::crc32::Digest::new_with_initial(crc::crc32::IEEE, crc::crc32::checksum_ieee(&comp1[..]));
                c.write(&comp2[..]);
                c.sum32()
            };
            if self.encrypt {
                encrypt_v4(&mut comp1[..], self.version, g1_key1, g1_key2);
                encrypt_v4(&mut comp2[..], self.version, g2_key1, g2_key2);
            }

            info.crc32.set(crc);

            let crcg1 = if comp1.len() > 0 { crc::crc32::checksum_ieee(&comp1[..]) } else { 0 };
            let crcg2 = if comp2.len() > 0 { crc::crc32::checksum_ieee(&comp2[..]) } else { 0 };

            let mut gh = crate::read::IceGroupHeader::default();
            gh.groups[0].size.set(uncompressed_size1 as u32);
            gh.groups[0].compressed_size.set(compressed_size1 as u32);
            gh.groups[0].file_count.set(filecount1 as u32);
            gh.groups[0].crc32.set(crcg1);
            gh.groups[1].size.set(uncompressed_size2 as u32);
            gh.groups[1].compressed_size.set(compressed_size2 as u32);
            gh.groups[1].file_count.set(filecount2 as u32);
            gh.groups[1].crc32.set(crcg2);
            gh.group1_size.set(compressed_size1 as u32);
            gh.group2_size.set(compressed_size2 as u32);
            // key is unset in v4-9
            if self.encrypt {
                let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&gh_key[..]).unwrap(), &Default::default());
                blowfish.encrypt(gh.as_bytes_mut(), std::mem::size_of::<crate::read::IceGroupHeader>()).unwrap();
            }

            // write remaining stuff
            sink.write_all(header.as_bytes())?;
            sink.write_all(info.as_bytes())?;
            if self.version > 4 {
                sink.write_all(&[0u8; 0x10])?;
            }
            sink.write_all(&table[..])?;
            sink.write_all(gh.as_bytes())?;
            sink.write_all(&comp1[..])?;
            sink.write_all(&comp2[..])?;

            Ok(())
        }
    }
}

fn encrypt_v4(buf: &mut [u8], version: u32, key1: u32, key2: u32) {
    assert!((4..=9).contains(&version));
    let size = buf.len();

    if size == 0 {
        return;
    }

    if (version < 5 && size <= 0x19000) || (size <= 0x25800) {
        let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&key2.to_le_bytes()[..]).unwrap(), &Default::default());
        blowfish.encrypt(&mut buf[..size - size % 8], size - size % 8).unwrap();
    }
    let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&key1.to_le_bytes()[..]).unwrap(), &Default::default());
    blowfish.encrypt(&mut buf[..size - size % 8], size - size % 8).unwrap();

    let shift = if version < 5 { 16 } else { version + 5 };
    let xorbyte = ((key1 ^ (key1 >> shift)) & 0xFF) as u8;
    for b in buf[..].iter_mut() {
        if *b != 0 && *b != xorbyte {
            *b = *b & 0xFF ^ xorbyte;
        }
    }
}

/// An IO sink for writing bytes to a file before completing its insertion into
/// an in-progress ICE archive.
pub struct IceFileWriter<'a> {
    writer: &'a mut IceWriter,
    group: Group,
    ext: AsciiString,
    name: AsciiString,
    buf: Vec<u8>,
}

impl<'a> IceFileWriter<'a> {
    /// Consume this writer, adding the file to the referenced IceWriter.
    pub fn finish(self) {
        let IceFileWriter {
            writer,
            group,
            ext,
            name,
            buf,
        } = self;

        let files = match group {
            Group::Group1 => &mut writer.files[0],
            Group::Group2 => &mut writer.files[1],
        };

        files.push(FileEntry {
            ext,
            name,
            buf,
        });
    }
}

impl<'a> Write for IceFileWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.buf.flush()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::read::IceArchive;

    use std::io::Cursor;

    fn test(version: u32) -> Vec<u8> {
        let mut fw = IceWriter::new(version, true, true, false).unwrap();
        {
            let mut f = fw.begin_file(AsciiStr::from_ascii("hello1.txt").unwrap(), AsciiStr::from_ascii("txt").unwrap(), Group::Group1);
            f.write_all(b"hello world").unwrap();
            f.finish();
        }
        {
            let mut f = fw.begin_file(AsciiStr::from_ascii("hello2.txt").unwrap(), AsciiStr::from_ascii("txt").unwrap(), Group::Group2);
            f.write_all(b"hello world").unwrap();
            f.finish();
        }
        let mut fb = Vec::new();
        fw.finish(&mut fb).unwrap();
        let mut ia = IceArchive::new(Cursor::new(&fb)).unwrap();
        ia.unpack_group(Group::Group1).unwrap();
        ia.unpack_group(Group::Group2).unwrap();
        println!("Group 1:");
        for f in ia.iter_group(Group::Group1).unwrap() {
            println!("\t{}", f.name().unwrap());
        }
        println!("Group 2:");
        for f in ia.iter_group(Group::Group2).unwrap() {
            println!("\t{}", f.name().unwrap());
        }
        fb
    }

    #[test]
    fn test_v3() {
        test(3);
    }

    #[test]
    fn test_v4() {
        test(4);
    }

    // #[test]
    // fn test_v5() {
    //     test(5);
    // }

    // #[test]
    // fn test_v6() {
    //     test(6);
    // }

    // #[test]
    // fn test_v7() {
    //     test(7);
    // }

    // #[test]
    // fn test_v8() {
    //     test(8);
    // }

    // #[test]
    // fn test_v9() {
    //     test(9);
    // }
}
