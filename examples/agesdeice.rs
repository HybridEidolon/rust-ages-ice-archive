use ages_ice_archive::{Group, IceArchive, IceGroupIter};

use std::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::Context;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "agesdeice", about = "Tool for unpacking PSO2 ICE archives.")]
struct Args {
    #[structopt(parse(from_os_str), help = "ICE archive to unpack")]
    input: PathBuf,

    #[structopt(long = "ice-version", help = "Print the ICE version of the archive, instead of unpacking")]
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

fn list_files_in_group(ia: &IceArchive, group: Group, indent: bool) -> Result<(), anyhow::Error> {
    let data = ia.decompress_group(group)?;
    let iter = IceGroupIter::new(&data[..], ia.group_count(group))
        .context("Failed to iterate over group")?;
    for f in iter {
        let name_result = f.name()
            .context("Unable to read file name");
        match name_result {
            Ok(n) => {
                if indent {
                    println!("\t{}", n);
                } else {
                    println!("{}", n);
                }
            },
            Err(e) => eprintln!("{:?}", e),
        }
    }
    Ok(())
}

fn write_group_iter(iter: IceGroupIter, out: &Path) -> Result<(), anyhow::Error> {
    for f in iter {
        let name_str = match f.name().context("Can't write file due to invalid file name") {
            Ok(n) => n,
            Err(e) => {
                eprintln!("agesdeice: {:?}", e);
                continue;
            },
        };
        let path = out.join(name_str);
        std::fs::write(&path, f.data())
            .with_context(|| format!("Failed to write file {}", path.to_string_lossy()))?;
    }
    Ok(())
}

fn extract_archive(ia: &IceArchive, out: &Path) -> Result<(), anyhow::Error> {
    let output_g1 = out.join("1");
    let output_g2 = out.join("2");

    std::fs::create_dir_all(&output_g1)
        .context("Failed to create group 1 output directory")?;
    std::fs::create_dir_all(&output_g2)
        .context("Failed to create group 2 output directory")?;

    let g1_data = ia.decompress_group(Group::Group1)
        .context("Failed to decompress group 1")?;
    let g2_data = ia.decompress_group(Group::Group2)
        .context("Failed to decompress group 2")?;

    let g1_iter = IceGroupIter::new(&g1_data[..], ia.group_count(Group::Group1))
        .context("Failed to iterate over group 1 files")?;
    let g2_iter = IceGroupIter::new(&g2_data[..], ia.group_count(Group::Group2))
        .context("Failed to iterate over group 2 files")?;

    write_group_iter(g1_iter, &output_g1)
        .context("Failed to write group 1 files")?;
    write_group_iter(g2_iter, &output_g2)
        .context("Failed to write group 2 files")?;

    Ok(())
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

    let ia = IceArchive::load(File::open(&args.input)?)
        .with_context(|| format!("Failed to load ICE archive from file {}", args.input.to_string_lossy()))?;

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

    if args.ice_version {
        println!("{}", ia.version());
        return Ok(());
    } else if args.list2 {
        list_files_in_group(&ia, Group::Group2, false)
            .context("Failed to list group 2 files")?;
        return Ok(());
    } else if args.list1 {
        list_files_in_group(&ia, Group::Group1, false)
            .context("Failed to list group 1 files")?;
        return Ok(());
    } else if args.list {
        println!("Group 1");
        list_files_in_group(&ia, Group::Group1, true)
            .context("Failed to list group 1 files")?;
        println!("\n");
        println!("Group 2");
        list_files_in_group(&ia, Group::Group2, true)
            .context("Failed to list group 2 files")?;
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

    extract_archive(&ia, &args.output)
        .with_context(|| format!("Failed to extract archive from file {} to {}", args.input.to_string_lossy(), args.output.to_string_lossy()))?;

    Ok(())
}
