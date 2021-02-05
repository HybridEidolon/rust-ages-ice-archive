use ages_ice_archive::{Group, IceWriter};
use ascii::IntoAsciiString;

use std::{error::Error, path::Path};
use std::fs::File;
use std::path::PathBuf;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "agesice", about = "Tool for packing PSO2 ICE archives.")]
struct Args {
    #[structopt(short = "1", parse(from_os_str), default_value = "1", help = "Path of files to pack in group 1")]
    input1: PathBuf,

    #[structopt(short = "2", parse(from_os_str), default_value = "2", help = "Path of files to pack in group 2")]
    input2: PathBuf,

    #[structopt(short = "v", long = "ice-version", default_value = "4", help = "Use the given ICE version")]
    ice_version: u32,

    #[structopt(short = "o", long = "output", parse(from_os_str), default_value = "out.ice", help = "Filename to pack to")]
    output: PathBuf,

    #[structopt(short = "k", long = "oodle", help = "Compress with Oodle. Ignored if -c is not set")]
    oodle: bool,

    #[structopt(short = "e", long = "encrypt", help = "Encrypt the archive")]
    encrypt: bool,

    #[structopt(short = "c", long = "compress", help = "Compress the archive")]
    compress: bool,
}

fn do_group(ice_writer: &mut IceWriter, dir: &Path, group: Group) -> Result<(), Box<dyn Error>> {
    let dir = std::fs::read_dir(dir)?;
    for entry in dir {
        match entry {
            Ok(f) => {
                let string_fname = f.file_name().to_string_lossy().into_owned();
                let fname = match ascii::AsciiStr::from_ascii(&string_fname) {
                    Ok(f) => f,
                    Err(_) => {
                        eprintln!("agesice: file {:?} has non-ascii name", f.path());
                        continue
                    },
                };
                let fext = match f.path().extension() {
                    Some(o) => {
                        let string_fext = o.to_string_lossy().into_owned();
                        match ascii::AsciiString::from_ascii(string_fext) {
                            Ok(f) => f.into_ascii_string()?,
                            Err(_) => {
                                eprintln!("agesice: file {:?} has non-ascii file extension", f.path());
                                continue
                            },
                        }
                    },
                    None => {
                        eprintln!("agesice: file {:?} has no file extension", f.path());
                        continue
                    },
                };
                let mut file_writer = ice_writer.begin_file(fname, &fext, group);
                let mut file = File::open(f.path())?;
                std::io::copy(&mut file, &mut file_writer)?;
                file_writer.finish();
            },
            Err(e) => {
                eprintln!("agesice: failed to open file in dir: {}", e);
                continue
            },
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();
    if args.input1.exists() && !args.input1.is_dir() {
        eprintln!("agesice: input1 path is not a directory");
        std::process::exit(1);
    }
    if !args.input2.exists() && !args.input2.is_dir() {
        eprintln!("agesice: input2 path is not a directory");
        std::process::exit(1);
    }

    if args.ice_version < 3 || args.ice_version > 4 {
        eprintln!("agesice: ice versions other than 3 and 4 are not supported");
        std::process::exit(1);
    }

    if cfg!(not(all(feature = "oodle", any(target_os = "linux", target_os = "windows")))) && args.oodle {
        eprintln!("agesice: oodle compression not available");
        std::process::exit(1);
    }

    let mut ice_writer = IceWriter::new(args.ice_version, args.compress, args.encrypt, args.oodle)?;

    if args.input1.exists() {
        do_group(&mut ice_writer, args.input1.as_ref(), Group::Group1)?;
    }
    if args.input2.exists() {
        do_group(&mut ice_writer, args.input2.as_ref(), Group::Group2)?;
    }

    ice_writer.finish(File::create(args.output)?)?;

    Ok(())
}
