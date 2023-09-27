use std::path::{Path, PathBuf};
use directories::ProjectDirs;

pub fn get_base_file_path() -> String {
    /*
    ! old method
    * Do not use this
    ? Commented and not removed for legacy purposes
     let is_windows = cfg!(windows);
     let path_buf = match env::var("APPDATA").ok() {
         Some(appdata) if is_windows => {
             let mut path = PathBuf::from(appdata);
             path.push("muffon_encryptor");
             path
         }
         _ => {
             let mut home = env::var("HOME").expect("HOME environment variable not found");
             home.push_str("/.config/muffon_encryptor");
             PathBuf::from(home)
         }
     }; 
     */

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
