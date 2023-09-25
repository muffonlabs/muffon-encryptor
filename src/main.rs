use std::io;
use std::env;
use std::path::PathBuf;
use std::fs::File;

fn get_master_password_file_path() -> String {
    let is_windows = cfg!(windows);

    let mut path_buf = match env::var("APPDATA").ok() {
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

    // Check if folder exists and create it if it doesn't
    if !path_buf.exists() {
        std::fs::create_dir_all(&path_buf).expect("Failed to create directory");
    }

    // Add "master_password.txt" to the path
    path_buf.push("master_password.txt");

    // Create the file if it doesn't exist
    if !path_buf.exists() {
        File::create(&path_buf).expect("Failed to create file");
    }

    path_buf.to_string_lossy().into_owned()
}

#[tokio::main]
async fn main() {
    let stdin = io::stdin();
    let args: Vec<String> = env::args().skip(1).collect();
    println!("{}", get_master_password_file_path());
}
