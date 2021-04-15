use ages_ice_archive::{Group, IceArchive, IceGroupIter};

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

    #[structopt(short = "d", long = "debug", help = "Output diagnostic data for debugging")]
    debug: bool,
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

    let ia = IceArchive::load(File::open(&args.input)?)?;

    if args.debug {
        eprintln!("ICE archive \"{}\"", args.input.to_string_lossy());
        eprintln!("Version: {}", ia.version());
        eprintln!("Is Encrypted: {}", ia.is_encrypted());
        eprintln!("Is Oodle: {}", ia.is_oodle());

        eprintln!("Group 1");
        eprintln!("\tFile count: {}", ia.group_count(Group::Group1));
        eprintln!("\tSize: {}", ia.group_size(Group::Group1));
        eprintln!("\tCompressed Size: {}", ia.group_data(Group::Group1).len());
        eprintln!("\tCompressed: {}", ia.is_compressed(Group::Group1));
        eprintln!("");
        eprintln!("Group 2");
        eprintln!("\tFile count: {}", ia.group_count(Group::Group2));
        eprintln!("\tSize: {}", ia.group_size(Group::Group2));
        eprintln!("\tCompressed Size: {}", ia.group_data(Group::Group2).len());
        eprintln!("\tCompressed: {}", ia.is_compressed(Group::Group2));
    }

    let g1_data = ia.decompress_group(Group::Group1)?;
    let g2_data = ia.decompress_group(Group::Group2)?;

    if args.ice_version {
        println!("{}", ia.version());
        return Ok(());
    } else if args.list2 {
        let g2_iter = IceGroupIter::new(&g2_data[..], ia.group_count(Group::Group2)).unwrap();
        for f in g2_iter {
            match f.name() {
                Ok(n) => println!("{}", n),
                Err(e) => eprintln!("{}", e),
            }
        }
        return Ok(());
    } else if args.list1 {
        let g1_iter = IceGroupIter::new(&g1_data[..], ia.group_count(Group::Group1)).unwrap();
        for f in g1_iter {
            match f.name() {
                Ok(n) => println!("{}", n),
                Err(e) => eprintln!("{}", e),
            }
        }
        return Ok(());
    } else if args.list {
        let g1_iter = IceGroupIter::new(&g1_data[..], ia.group_count(Group::Group1)).unwrap();
        let g2_iter = IceGroupIter::new(&g2_data[..], ia.group_count(Group::Group2)).unwrap();
        println!("Group 1");
        for f in g1_iter {
            match f.name() {
                Ok(n) => println!("\t{}", n),
                Err(e) => eprintln!("\t{}", e),
            }
        }
        println!("\n");
        println!("Group 2");
        for f in g2_iter {
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

    let g1_iter = IceGroupIter::new(&g1_data[..], ia.group_count(Group::Group1)).unwrap();
    let g2_iter = IceGroupIter::new(&g2_data[..], ia.group_count(Group::Group2)).unwrap();

    for f in g1_iter {
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

    for f in g2_iter {
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
