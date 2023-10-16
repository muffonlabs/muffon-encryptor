mod modules;
use aes_gcm::{Aes256Gcm, Key, aead::{OsRng, generic_array::GenericArray}, aead::Aead, AeadCore, KeyInit};
use base64::{Engine as _, engine::{self, general_purpose}, alphabet};
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
use std::{io, env, io::Read, io::Write, path::Path, fs::File, collections::HashMap, num::NonZeroU32};
use ring::pbkdf2;

const PBKDF2_ROUNDS: u32 = 100_000;
const SALT_LEN: usize = 16;

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

// returns a bool and a string
fn input_master_password(master_password_path: &str, prompt: &str) -> bool {
    println!("{}", prompt);
    let current_password = rpassword::read_password().unwrap();
    let contents = std::fs::read_to_string(&master_password_path).unwrap();
    if verify_master_password(&current_password, &contents) {
        return true;
    }
    false
}

fn get_master_password(prompt: &str) -> String {
    println!("{}", prompt);
    let current_password = rpassword::read_password().unwrap();
    current_password
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

#[derive(Clone)]
struct Block {
    data: Vec<u8>,
    nonce: Vec<u8>
}

fn encrypt(data: &[u8], key_byte: &[u8]) -> Block {
    let key: &Key<Aes256Gcm> = key_byte.into();
    let cipher = Aes256Gcm::new(&key);

    let nonce = Aes256Gcm::generate_nonce(OsRng);

    let encrypted_data = match cipher.encrypt(&nonce, data) {
        Ok(encrpted) => {
            let e = Block { data: encrpted, nonce:nonce.to_vec() };
            e
        }
        Err(err) => {
            panic!("could not encrypt data: {:?}", err);
        }
    };
    encrypted_data
}

fn decrypt(encrypted_data: Block,  password_byte: &[u8]) -> Vec<u8> {
    let key: &Key<Aes256Gcm> = password_byte.into();
    let nonce = encrypted_data.nonce;
    let data = encrypted_data.data;

    let cipher = Aes256Gcm::new(&key);
    let op = cipher.decrypt(GenericArray::from_slice(&nonce), data.as_slice()).unwrap();
    op
}

fn start_menu() {
    let master_password_path = get_master_password_file_path();
    let input_master_password = get_master_password("Master password: ");
    let contents = std::fs::read_to_string(&master_password_path).unwrap();
    let master_correct = verify_master_password(&input_master_password, &contents);
    if !master_correct {
        println!("Incorrect master password. Please try again.");
        return;
    } else {
        println!("Master password correct! You're in!");
    }

    // Using PBKDF2 to derive a key from the password
    let salt: [u8; SALT_LEN] = [0; SALT_LEN]; // this is a constant salt for now
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ROUNDS).unwrap(),
        &salt,
        input_master_password.as_bytes(),
        &mut key,
    );

    let stdin = io::stdin();

    let mut password_map: HashMap<String, Block> = HashMap::new();

    loop {
        println!("Welcome to Muffon Encryptor");
        println!("Please select an option:");
        println!("0. List encrypted passwords and secrets");
        println!("1. List passwords and secrets");
        println!("2. Add a new password/secret");
        println!("3. Delete a password/secret");
        println!("4. Exit");
        let mut input = String::new();
        stdin.read_line(&mut input).expect("Failed to read line");
        let input = input.trim();
        match input {
            "0" => {
                println!("Writing unencrypted passwords to file...");
                let passwords_path = get_passwords_file_path();
                let mut file = File::create(&passwords_path).expect("Unable to create file");
                for (username, encrypted_password) in &password_map {
                    let enc_base64 = general_purpose::STANDARD_NO_PAD.encode(encrypted_password.data.as_slice());
                    let line = format!("{}: {}: {}\n", username, enc_base64, encrypted_password.nonce.iter().map(|b| format!("{:02x}", b)).collect::<String>());
                    file.write_all(line.as_bytes()).expect("Unable to write data");
                }
            },
            "1" => {
                println!("Listing passwords...");
                for (username, encrypted_password) in &password_map {
                    let password = decrypt(encrypted_password.clone(), &key);
                    println!("{}: {}", username, String::from_utf8(password).unwrap());
                }
            },
            "2" => {
                println!("Enter username:");
                let mut username = String::new();
                stdin.read_line(&mut username).expect("Failed to read username");
                let username = username.trim().to_string();

                println!("Enter password:");
                let mut password = String::new();
                stdin.read_line(&mut password).expect("Failed to read password");
                let password = password.trim().as_bytes().to_vec();
                println!("Encrypting...");
                let encrypted_password = encrypt(&password, &key);
                println!("Encrypted!");
                password_map.insert(username, encrypted_password);
            },
            "3" => {
                println!("Enter username to delete:");
                let mut username = String::new();
                stdin.read_line(&mut username).expect("Failed to read username");
                let username = username.trim().to_string();
                
                if password_map.remove(&username).is_some() {
                    println!("Deleted password for {}", username);
                } else {
                    println!("No password found for {}", username);
                }
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