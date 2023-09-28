mod modules;
use modules::{
    bcrypt_mods::{
        encrypt_master_password,
        verify_master_password
    },
    file_path_mods::{
        get_master_password_file_path,
        get_passwords_file_path
    }
};
use std::{io, env, io::Read, io::Write, path::Path, fs::File};

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

fn input_master_password(master_password_path: &str, prompt: &str) -> bool {
    println!("{}", prompt);
    let current_password = rpassword::read_password().unwrap();
    let contents = std::fs::read_to_string(&master_password_path).unwrap();
    if verify_master_password(&current_password, &contents) {
        return true;
    }
    false
}

fn reset_master_password() {
    let master_password_path = get_master_password_file_path();
    // if the master password is already set, ask for it
    if is_master_password_set() {
        let master_correct = input_master_password(&master_password_path, "Current master password: ");
        if !master_correct {
            println!("Incorrect master password. Please try again.");
            return;
        } else {
            println!("Master password correct! You're in!");
        }
    }
    // continue with setting the new master password
    println!("New master password: ");
    let new_password = rpassword::read_password().unwrap();
    if !validate_master_password(&new_password) {
        println!("Password does not match security standards. Please try again.");
        return;
    } else {
        log::info!("Encrypting...");
        let hashed_password = encrypt_master_password(&new_password);
        let mut file = File::create(&master_password_path).expect("Unable to create file");
        file.write_all(hashed_password.as_bytes()).expect("Unable to write data");
        println!("Master password set successfully!");
    }
    // TODO: decrypt all the passwords using the old master password and encrypt them using the new one
}

fn start_menu() {
    let master_password_path = get_master_password_file_path();
    let master_correct = input_master_password(&master_password_path, "Master password: ");
    if !master_correct {
        println!("Incorrect master password. Please try again.");
        return;
    } else {
        println!("Master password correct! You're in!");
    }
    let stdin = io::stdin();
    loop {
        println!("Welcome to Muffon Encryptor");
        println!("Please select an option:");
        println!("1. List passwords and secrets");
        println!("2. Add a new password/secret");
        println!("3. Delete a password/secret");
        println!("4. Exit");
        let mut input = String::new();
        stdin.read_line(&mut input).expect("Failed to read line");
        let input = input.trim();
        match input {
            "1" => {
                println!("Listing passwords...");
                println!("TBD");
            },
            "2" => {
                println!("TBD");
            },
            "3" => {
                println!("TBD");
            },
            "4" => {
                println!("Goodbye!");
                return;
            },
            _ => {
                println!("Invalid option. Please try again.");
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 0 {
        if !is_master_password_set() {
            println!("No master password set. Please set one using the --setMasterPassword flag.");
        } else {
            start_menu();
        }
    } else {
        if args.contains(&"--setMasterPassword".to_string()) {
            reset_master_password();
        } else if args.contains(&"--help".to_string()) {
            println!("Usage: muffon-encryptor [OPTION]...");
            println!("Options:");
            println!("--setMasterPassword\t\tSet the master password");
            println!("--help\t\t\t\tShow this help message");
        } else {
            println!("Invalid options. Use --help for more information.");
        }
    }
}