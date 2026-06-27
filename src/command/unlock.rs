use std::path::PathBuf;

use arboard::Clipboard;
use super::common::{decrypt_blob, load_blob};

pub fn run(input: PathBuf) -> Result<(), String> {
    let blob = load_blob(&input)?;
    let master_password = crate::password::read("Master password: ")?;
    let plaintext = decrypt_blob(&blob, &master_password)?;
    let password = String::from_utf8(plaintext).map_err(|e| e.to_string())?;

    let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.set_text(password).map_err(|e| e.to_string())?;
    println!("Password copied to clipboard.");

    Ok(())
}
