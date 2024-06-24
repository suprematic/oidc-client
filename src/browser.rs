use anyhow::Result;
use std::process::Command;

#[cfg(target_os = "linux")]
pub fn open(uri: &str) -> Result<()> {
    let _ = Command::new("xdg-open").arg(uri).spawn()?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn open(uri: &str) -> Result<()> {
    let _ = Command::new("rundll32")
        .arg("url.dll,FileProtocolHandler")
        .arg(uri)
        .spawn()?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn open(uri: &str) -> Result<()> {
    let _ = Command::new("open").arg(uri).spawn()?;
    Ok(())
}
