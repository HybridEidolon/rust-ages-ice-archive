fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=ooz");
    cc::Build::new()
        .files(std::fs::read_dir("ooz")?.filter_map(|x| match x {
            Ok(x) if x.file_name().to_str()?.ends_with(".cpp") => Some(x.path()),
            _ => None,
        }))
        .compile("ooz");
    Ok(())
}
