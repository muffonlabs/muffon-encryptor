
use bcrypt::hash;

pub fn encrypt_master_password(master_password: &str) -> String {
    hash(master_password.as_bytes(), 12).unwrap()
}