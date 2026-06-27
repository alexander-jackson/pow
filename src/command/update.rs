use std::path::PathBuf;

use crate::LockDuration;
use super::common::{decrypt_blob, encrypt_and_write, load_blob};

pub fn run(time: LockDuration, input: PathBuf, output: PathBuf) -> Result<(), String> {
    let blob = load_blob(&input)?;
    let master_password = crate::password::read("Master password: ")?;
    let account_password = decrypt_blob(&blob, &master_password)?;
    encrypt_and_write(&master_password, &account_password, time.0, &output)
}
