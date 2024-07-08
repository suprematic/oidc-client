#![allow(unused)]
include!("src/config.rs");

use clap_complete::shells;
use std::env;
use std::io::Error;

fn main() -> Result<(), Error> {
    let outdir = match env::var_os("OUT_DIR") {
        None => return Ok(()),
        Some(outdir) => outdir,
    };
    let mut cmd = cli();
    /*let path = */
    clap_complete::generate_to(
        shells::Bash,
        &mut cmd,      // We need to specify what generator to use
        "oidc-client", // We need to specify the bin name manually
        &outdir,       // We need to specify where to write to
    )?;
    // println!("cargo:info=completion file is generated: {path:?}");
    /*let path = */
    clap_complete::generate_to(
        shells::Zsh,
        &mut cmd,      // We need to specify what generator to use
        "oidc-client", // We need to specify the bin name manually
        &outdir,       // We need to specify where to write to
    )?;
    // println!("cargo:info=completion file is generated: {path:?}");
    Ok(())
}
