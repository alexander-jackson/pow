pub fn read(prompt: &str) -> Result<String, String> {
    let password = rpassword::prompt_password(prompt).map_err(|e| e.to_string())?;

    Ok(password)
}
