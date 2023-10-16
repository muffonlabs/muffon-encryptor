use directories::ProjectDirs;
use std::path::{Path, PathBuf};

pub fn get_base_file_path() -> String {
    let path_buf: PathBuf = match ProjectDirs::from("com", "Muffon Labs", "Muffon-Encryptor") {
        Some(proj_dirs) => {
            let path: &Path = proj_dirs.data_local_dir();
            PathBuf::from(path)
        }
        _ => panic!("Error: Couldn't get ProjectDirs"),
    };

    if !path_buf.exists() {
        std::fs::create_dir_all(&path_buf).expect("Failed to create directory");
    }

    path_buf.to_string_lossy().into_owned()
}