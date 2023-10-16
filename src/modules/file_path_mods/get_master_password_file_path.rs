use crate::modules::file_path_mods::get_base_file_path;

use std::{fs::File, path::PathBuf};

pub fn get_master_password_file_path() -> String {
    let mut path_buf = PathBuf::from(get_base_file_path());

    // Add "master_password.txt" to the path
    path_buf.push("hash.muf");

    // Create the file if it doesn't exist
    if !path_buf.exists() {
        File::create(&path_buf).expect("Failed to create file");
    }

    path_buf.to_string_lossy().into_owned()
}