mod modules;
use modules::bcrypt_mods::{encrypt_master_password, verify_master_password};
use std::{io, env, io::Read, io::Write, path::{Path, PathBuf}, fs::File};

fn get_base_file_path() -> String {
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

    // Check if folder exists and create it if it doesn't
    if !path_buf.exists() {
        std::fs::create_dir_all(&path_buf).expect("Failed to create directory");
    }

    path_buf.to_string_lossy().into_owned()
}

fn get_master_password_file_path() -> String {
    
    let mut path_buf = PathBuf::from(get_base_file_path());

    // Add "master_password.txt" to the path
    path_buf.push("hash.muf");

    // Create the file if it doesn't exist
    if !path_buf.exists() {
        File::create(&path_buf).expect("Failed to create file");
    }

    path_buf.to_string_lossy().into_owned()
}

fn get_passwords_file_path() -> String {
    
    let mut path_buf = PathBuf::from(get_base_file_path());

    // Add "master_password.txt" to the path
    path_buf.push("pws.muf");

    // Create the file if it doesn't exist
    if !path_buf.exists() {
        File::create(&path_buf).expect("Failed to create file");
    }

    path_buf.to_string_lossy().into_owned()
}

fn delete_password_files() -> Result<(), std::io::Error> {
    let passwords_path = get_passwords_file_path();
    std::fs::remove_file(passwords_path)?;
    let master_password_path = get_master_password_file_path();
    std::fs::remove_file(master_password_path)?;
    Ok(())
}

fn is_master_password_set() -> bool {
    let master_password_path = get_master_password_file_path();
    if Path::new(&master_password_path).exists() {
        // check if file content is not empty
        let mut file = File::open(&master_password_path).expect("file not found");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
        .expect("something went wrong reading the file");
        return !contents.is_empty();
    } else {
        delete_password_files().ok();
        false
    }
}

fn validate_master_password(password: &str) -> bool {
    let mut valid = true;
    if password.len() < 8 {
        println!("Password must be at least 8 characters long.");
        valid = false;
    }
    valid
}

fn reset_master_password() {
    let stdin = io::stdin();
    let master_password_path = get_master_password_file_path();
    // if the master password is already set, ask for it
    if is_master_password_set() {
        println!("Current master password: ");
        let mut current_password = String::new();
        stdin.read_line(&mut current_password).expect("Failed to read line");
        let current_password = current_password.trim();
        let contents = std::fs::read_to_string(&master_password_path).unwrap();
        if !verify_master_password(current_password, &contents) {
            println!("Incorrect password.");
            return;
        } else {
            println!("Correct password! You're in!");
        }
    }
    // continue with setting the new master password
    let mut new_password = String::new();
    println!("Enter new master password: ");
    stdin.read_line(&mut new_password).expect("Failed to read line");
    new_password = new_password.trim().to_string();
    if !validate_master_password(&new_password) {
        println!("Password does not match security standards,. Please try again.");
        return;
    } else {
        println!("Encrypting...");
        let hashed_password = encrypt_master_password(&new_password);
        let mut file = File::create(&master_password_path).expect("Unable to create file");
        file.write_all(hashed_password.as_bytes()).expect("Unable to write data");
        println!("Master password set successfully!");
    }
    // TODO: decrypt all the passwords using the old master password and encrypt them using the new one
}



#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 0 {
        if !is_master_password_set() {
            println!("No master password set. Please set one using the --setMasterPassword flag.");
        } else {
            // start
        }
    } else {
        if args.contains(&"--setMasterPassword".to_string()) {
            reset_master_password();
        }
    }
}