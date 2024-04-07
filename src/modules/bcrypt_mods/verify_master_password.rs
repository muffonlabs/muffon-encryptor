use bcrypt::verify;

pub fn verify_master_password(password: &str, hashed: &str) -> bool {
    verify(password.as_bytes(), hashed).unwrap_or(false) // TODO: maybe a better way to handle this?
}