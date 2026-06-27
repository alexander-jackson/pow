use std::path::PathBuf;

use crate::LockDuration;
use super::common::encrypt_and_write;

pub fn run(time: LockDuration, output: PathBuf) -> Result<(), String> {
    let master_password = crate::password::read("Master password: ")?;
    let account_password = crate::password::read("Account password to lock: ")?;
    let confirm = crate::password::read("Confirm account password: ")?;

    if account_password != confirm {
        return Err("Passwords do not match.".into());
    }

    encrypt_and_write(&master_password, account_password.as_bytes(), time.0, &output)
}
