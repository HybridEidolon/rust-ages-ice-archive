# ages-ice-archive: ICE archive library for Rust

[![CI](https://github.com/HybridEidolon/rust-ages-ice-archive/workflows/CI/badge.svg)](https://github.com/HybridEidolon/rust-ages-ice-archive/actions?query=workflow%3ACI)
[![Crate](https://img.shields.io/crates/v/ages-ice-archive.svg)](https://crates.io/crates/ages-ice-archive)
[![API](https://docs.rs/ages-ice-archive/badge.svg)](https://docs.rs/ages-ice-archive)

Types for loading and writing ICE archives.

ICE is an asset storage format used by SEGA's _Phantasy Star Online 2_, named
after its magic prefix in its header.

This crate should work out-of-the-box on WebAssembly.

You may also install this crate via `cargo install` to get CLI utilities for
unpacking and packing ICE files from the filesystem. These are examples within
this package's repository, named `agesdeice` and `agesice` respectively.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
ages-ice-archive = "0.1"
```

Within your code:

```rust
use std::fs::File;
use std::error::Error;

use ages_ice_archive::{Group, IceArchive};

fn main() -> Result<(), Box<dyn Error>> {
    let file = File::open("my.ice")?;
    let mut archive = IceArchive::new(file)?;

    archive.unpack_group(Group::Group1)?;
    println!("Files in Group 1:");
    for f in archive.iter_group(Group::Group1).unwrap() {
        if let Ok(name) = f.name() {
            println!("\t{} ({} bytes)", name, f.data().len());
        } else {
            println!("\t(non-ascii file name)");
        }
    }

    archive.unpack_group(Group::Group2)?;
    println!("Files in Group 2:");
    for f in archive.iter_group(Group::Group2).unwrap() {
        if let Ok(name) = f.name() {
            println!("\t{} ({} bytes)", name, f.data().len());
        } else {
            println!("\t(non-ascii file name) ({} bytes)", f.data().len());
        }
    }

    Ok(())
}
```

## License

`ages-ice-archive` is dual-licensed for compatibility with the rest of the Rust
public ecosystem.

`ages-ice-archive` is distributed under the terms of both the MIT license and
the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
