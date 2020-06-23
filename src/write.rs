use crate::Group;

use std::io::{self, Cursor, Read, Write};

use ages_prs::ModernPrsEncoder;
use ascii::{AsciiStr, AsciiString};
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::NoPadding;
use blowfish::BlowfishLE;
use blowfish::block_cipher::NewBlockCipher;
use byteorder::{LittleEndian as LE, WriteBytesExt};

pub struct IceWriter {
    files: [Vec<FileEntry>; 2],
    version: u32,
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
        let padded_size = self.buf.len() + padding_bytes + 0x60;
        out.write_all(self.ext.as_bytes());
        if self.ext.len() % 4 != 0 {
            for _ in std::iter::repeat(0).take(4 - self.ext.len() % 4) {
                out.write_u8(0)?;
            }
        }
        out.write_u32::<LE>(padded_size as u32)?;
        out.write_u32::<LE>(self.buf.len() as u32)?;
        out.write_u32::<LE>(0x60)?;
        out.write_u32::<LE>(self.name.len() as u32 + 1)?;
        for _ in std::iter::repeat(0).take(44) {
            out.write_u8(0)?;
        }
        out.write_all(self.name.as_bytes())?;
        for _ in std::iter::repeat(0).take(32 - self.name.len()) {
            out.write_u8(0)?;
        }
        out.write_all(&self.buf[..]);
        for _ in std::iter::repeat(0).take(padding_bytes) {
            out.write_u8(0)?;
        }
        Ok(padded_size)
    }
}

impl IceWriter {
    pub fn new(version: u32) -> IceWriter {
        assert!((3..=9).contains(&version));

        IceWriter {
            version,
            files: Default::default(),
        }
    }

    pub fn begin_file<'a>(&'a mut self, name: &AsciiStr, ext: &AsciiStr, group: Group) -> IceFileWriter<'a> {
        IceFileWriter {
            writer: self,
            name: name.to_owned(),
            ext: ext.to_owned(),
            group,
            buf: Vec::with_capacity(1024),
        }
    }

    pub fn finish<W: Write>(self, mut sink: W) -> io::Result<()> {
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

        let mut comp1 = Vec::with_capacity(g1.len() / 2);
        let mut comp2 = Vec::with_capacity(g2.len() / 2);
        if g1.len() > 0 {
            ModernPrsEncoder::new(&mut comp1).write_all(&g1[..])?;
        }
        if g2.len() > 0 {
            ModernPrsEncoder::new(&mut comp2).write_all(&g2[..])?;
        }

        let comp1_padded_size = if comp1.len() / 16 == 0 { comp1.len() } else { comp1.len() + comp1.len() % 16 };
        let comp2_padded_size = if comp2.len() / 16 == 0 { comp2.len() } else { comp2.len() + comp2.len() % 16 };

        comp1.resize(comp1_padded_size, 0);
        comp2.resize(comp2_padded_size, 0);
        for b in comp1.iter_mut().chain(comp2.iter_mut()) {
            *b ^= 0x95;
        }

        let uncompressed_size1 = g1.len();
        let compressed_size1 = comp1_padded_size;
        let uncompressed_size2 = g2.len();
        let compressed_size2 = comp2_padded_size;
        let crcg1 = if comp1.len() > 0 { crc::crc32::checksum_ieee(&comp1[..]) } else { 0 };
        let crcg2 = if comp2.len() > 0 { crc::crc32::checksum_ieee(&comp2[..]) } else { 0 };

        // encryption is based on chosen version
        if self.version == 3 {
            // v3 encryption
            // use 1 key for both groups
            // header is unencrypted
            let source_key: u32 = rand::random();

            let key = uncompressed_size1 as u32 ^ uncompressed_size2 as u32 ^ 0u32 ^ source_key ^ 0xC8D7469Au32;

            let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&key.to_le_bytes()[..]).unwrap(), &Default::default());
            blowfish.encrypt(&mut comp1[..(compressed_size1 / 8) * 8], compressed_size1 / 8 * 8).unwrap();
            let blowfish: Ecb<BlowfishLE, NoPadding> = Ecb::new(BlowfishLE::new_varkey(&key.to_le_bytes()[..]).unwrap(), &Default::default());
            blowfish.encrypt(&mut comp2[..(compressed_size2 / 8) * 8], compressed_size2 / 8 * 8).unwrap();

            // write IceHeader
            sink.write_all(&b"ICE\0"[..])?;
            sink.write_u32::<LE>(0)?;
            sink.write_u32::<LE>(self.version)?;
            sink.write_u32::<LE>(0x80)?;

            // write IceGroupHeader
            sink.write_u32::<LE>(uncompressed_size1 as u32)?;
            sink.write_u32::<LE>(compressed_size1 as u32)?;
            sink.write_u32::<LE>(filecount1 as u32)?;
            sink.write_u32::<LE>(crcg1)?;
            sink.write_u32::<LE>(uncompressed_size2 as u32)?;
            sink.write_u32::<LE>(compressed_size2 as u32)?;
            sink.write_u32::<LE>(filecount2 as u32)?;
            sink.write_u32::<LE>(crcg2)?;
            sink.write_u32::<LE>(0)?; // g1 size
            sink.write_u32::<LE>(0)?; // g2 size
            sink.write_u32::<LE>(source_key)?; // key
            sink.write_u32::<LE>(0)?; // reserved (unused)

            // write IceInfo
            sink.write_u32::<LE>(0xFF)?;
            sink.write_u32::<LE>(0x12345678)?;
            sink.write_u32::<LE>(1)?;
            sink.write_u32::<LE>(0)?; // size todo
            sink.write_all(&[0u8; 0x30])?;

            // write groups
            sink.write_all(&comp1[..])?;
            sink.write_all(&comp2[..])?;

            Ok(())
        } else {
            // v4-9 encryption
            todo!("v4-9 write nyi")
        }
    }
}

pub struct IceFileWriter<'a> {
    writer: &'a mut IceWriter,
    group: Group,
    ext: AsciiString,
    name: AsciiString,
    buf: Vec<u8>,
}

impl<'a> IceFileWriter<'a> {
    pub fn finish(self) {
        let IceFileWriter {
            writer,
            group,
            ext,
            name,
            buf,
        } = self;

        let mut files = match group {
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

