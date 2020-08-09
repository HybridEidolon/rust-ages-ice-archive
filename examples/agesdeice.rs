use ages_ice_archive::{Group, IceArchive};

use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "agesdeice", about = "Tool for unpacking PSO2 ICE archives.")]
struct Args {
    #[structopt(parse(from_os_str), help = "ICE archive to unpack")]
    input: PathBuf,

    #[structopt(short = "v", long = "ice-version", help = "Print the ICE version of the archive, instead of unpacking")]
    ice_version: bool,

    #[structopt(short = "l", long = "list", help = "Print the list of files in both groups, instead of unpacking")]
    list: bool,

    #[structopt(short = "1", long = "list-1", help = "Print the list of files in group 1, instead of unpacking (overrides l)")]
    list1: bool,

    #[structopt(short = "2", long = "list-2", help = "Print the list of files in group 2, instead of unpacking (overrides l, 1)")]
    list2: bool,

    #[structopt(short = "o", long = "output", parse(from_os_str), default_value = ".", help = "Directory path to unpack to. Creates directories 1 and 2 for the groups.")]
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();

    if !args.input.exists() {
        eprintln!("agesdeice: input path not found");
        std::process::exit(1);
    }
    if !args.input.is_file() {
        eprintln!("agesdeice: input is not a file");
        std::process::exit(1);
    }

    let mut ia = IceArchive::new(File::open(&args.input)?)?;

    if args.ice_version {
        println!("{}", ia.version());
        return Ok(());
    } else if args.list2 {
        ia.unpack_group(Group::Group2)?;
        for f in ia.iter_group(Group::Group2).unwrap() {
            match f.name() {
                Ok(n) => println!("{}", n),
                Err(e) => eprintln!("{}", e),
            }
        }
        return Ok(());
    } else if args.list1 {
        ia.unpack_group(Group::Group1)?;
        for f in ia.iter_group(Group::Group1).unwrap() {
            match f.name() {
                Ok(n) => println!("{}", n),
                Err(e) => eprintln!("{}", e),
            }
        }
        return Ok(());
    } else if args.list {
        ia.unpack_group(Group::Group1)?;
        ia.unpack_group(Group::Group2)?;
        println!("Group 1");
        for f in ia.iter_group(Group::Group1).unwrap() {
            match f.name() {
                Ok(n) => println!("\t{}", n),
                Err(e) => eprintln!("\t{}", e),
            }
        }
        println!("\n");
        println!("Group 2");
        for f in ia.iter_group(Group::Group2).unwrap() {
            match f.name() {
                Ok(n) => println!("\t{}", n),
                Err(e) => eprintln!("\t{}", e),
            }
        }
        println!("\n");
        return Ok(());
    }

    if !args.output.exists() {
        eprintln!("agesdeice: output does not exist");
        std::process::exit(1);
    }

    if !args.output.is_dir() {
        eprintln!("agesdeice: output is not a directory");
        std::process::exit(1);
    }

    let mut output_g1 = args.output.clone();
    let mut output_g2 = args.output.clone();
    output_g1.push("1");
    output_g2.push("2");

    std::fs::create_dir_all(&output_g1)?;
    std::fs::create_dir_all(&output_g2)?;

    ia.unpack_group(Group::Group1)?;
    ia.unpack_group(Group::Group2)?;

    for f in ia.iter_group(Group::Group1).unwrap() {
        let name_str = match f.name() {
            Ok(n) => n,
            Err(_e) => {
                eprintln!("agesdeice: g1 file name invalid");
                continue;
            },
        };
        let mut path = output_g1.clone();
        path.push(name_str);
        let mut file = File::create(&path)?;
        file.write_all(f.data())?;
        // file.sync_all()?; -- DO NOT sync, otherwise this gets VERY slow
    }

    for f in ia.iter_group(Group::Group2).unwrap() {
        let name_str = match f.name() {
            Ok(n) => n,
            Err(_e) => {
                eprintln!("agesdeice: g2 file name invalid");
                continue;
            },
        };
        let mut path = output_g2.clone();
        path.push(name_str);
        let mut file = File::create(&path)?;
        file.write_all(f.data())?;
        // file.sync_all()?; -- DO NOT sync, otherwise this gets VERY slow
    }

    Ok(())
}
