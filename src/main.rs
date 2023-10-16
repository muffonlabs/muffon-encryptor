mod modules;
use aes_gcm::{
    aead::Aead,
    aead::{generic_array::GenericArray, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit,
};
use base64::{engine::general_purpose, Engine as _};
use modules::{
    bcrypt_mods::{encrypt_master_password, verify_master_password},
    file_path_mods::{get_master_password_file_path, get_passwords_file_path},
};
use ring::pbkdf2;
use std::{
    collections::HashMap, env, fs::File, io, io::Read, io::Write, num::NonZeroU32, path::Path,
};

const PBKDF2_ROUNDS: u32 = 100_000;
const SALT_LEN: usize = 16;

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ROUNDS).unwrap(),
        salt,
        password.as_bytes(),
        &mut key,
    );
    key
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

fn get_master_password(prompt: &str) -> String {
    println!("{}", prompt);
    let current_password = rpassword::read_password().unwrap();
    current_password
}

fn reset_master_password() {
    let master_password_path = get_master_password_file_path();
    // if the master password is already set, ask for it
    let mut old_master_password = String::new();
    let master_password_set = is_master_password_set();
    if master_password_set {
        old_master_password = get_master_password("Old master password: ");
        let contents = std::fs::read_to_string(&master_password_path).unwrap();
        let master_correct = verify_master_password(&old_master_password, &contents);
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
        file.write_all(hashed_password.as_bytes())
            .expect("Unable to write data");
        println!("Master password set successfully!");
    }
    if master_password_set {
        // decrypt all the passwords using the old master password and encrypt them using the new one
        let salt: [u8; SALT_LEN] = [0; SALT_LEN]; // this is a constant salt for now
        let key = derive_key(&old_master_password, &salt);
        let new_key = derive_key(&new_password, &salt);
        let passwords_path = get_passwords_file_path();
        let mut file = File::open(&passwords_path).expect("file not found");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("something went wrong reading the file");
        let lines = contents.split("\n");
        // create a hashmap of passwords using the old master password
        let mut password_map: HashMap<String, Password> = HashMap::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut split = line.split(": ");
            let identifier = split.next().unwrap();
            let id = split.next().unwrap();
            let username = split.next().unwrap();
            let password = split.next().unwrap();
            let nonce = split.next().unwrap();
            let password = password.trim();
            let nonce = nonce.trim();
            let password = general_purpose::STANDARD_NO_PAD
                .decode(password.as_bytes())
                .unwrap();
            let nonce = hex::decode(nonce).unwrap();
            let encrypted_password = Block {
                data: password,
                nonce,
            };
            password_map.insert(
                identifier.to_string(),
                Password {
                    id: id.parse::<u32>().unwrap(),
                    username: username.to_string(),
                    password: encrypted_password,
                },
            );
        }
        // decrypt and encrypt the passwords with the new master password
        let mut new_password_map: HashMap<String, Password> = HashMap::new();
        for (identifier, encrypted_password) in &password_map {
            let password = decrypt(encrypted_password.password.clone(), &key);
            let reencrypted_password = encrypt(&password, &new_key);
            new_password_map.insert(
                identifier.to_string(),
                Password {
                    id: encrypted_password.id,
                    username: encrypted_password.username.clone(),
                    password: reencrypted_password,
                },
            );
        }
        // overwrite the old passwords file with the new passwords
        let mut file = File::create(&passwords_path).expect("Unable to create file while migrating passwords");
        for (identifier, encrypted_password) in &new_password_map {
            let enc_base64 = general_purpose::STANDARD_NO_PAD
                .encode(encrypted_password.password.data.as_slice());
            let nonce_str = encrypted_password
                .password
                .nonce
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(); // convert to hex string
            let line = format!(
                "{}: {}: {}: {}: {}\n",
                identifier,
                encrypted_password.id,
                encrypted_password.username,
                enc_base64,
                nonce_str
            );
            file.write_all(line.as_bytes())
                .expect("Unable to write data while migrating passwords");
        }
        println!("Passwords migrated successfully!");
    }
}

#[derive(Clone)]
struct Block {
    data: Vec<u8>,
    nonce: Vec<u8>,
}

struct Password {
    id: u32,
    username: String,
    password: Block,
}

fn encrypt(data: &[u8], key_byte: &[u8]) -> Block {
    let key: &Key<Aes256Gcm> = key_byte.into();
    let cipher = Aes256Gcm::new(&key);

    let nonce = Aes256Gcm::generate_nonce(OsRng);

    let encrypted_data = match cipher.encrypt(&nonce, data) {
        Ok(encrpted) => {
            let e = Block {
                data: encrpted,
                nonce: nonce.to_vec(),
            };
            e
        }
        Err(err) => {
            panic!("could not encrypt data: {:?}", err);
        }
    };
    encrypted_data
}

fn decrypt(encrypted_data: Block, password_byte: &[u8]) -> Vec<u8> {
    let key: &Key<Aes256Gcm> = password_byte.into();
    let nonce = encrypted_data.nonce;
    let data = encrypted_data.data;

    let cipher = Aes256Gcm::new(&key);
    let op = cipher.decrypt(GenericArray::from_slice(&nonce), data.as_slice()).unwrap_or_else(|_| {
        delete_password_files().ok();
        println!("Unsolicited change of master password detected. All passwords including the Masterpassword have been deleted. Please restart the program.");
        std::process::exit(0);
    });
    op
}

fn determine_id(hmap: &HashMap<String, Password>) -> u32 {
    let mut id = 0;
    for (_, password) in hmap {
        if password.id > id {
            id = password.id;
        }
    }
    id + 1
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
    let key = derive_key(&input_master_password, &salt);

    let stdin = io::stdin();

    let mut password_map: HashMap<String, Password> = HashMap::new();

    loop {
        println!("Welcome to Muffon Encryptor");
        println!("Please select an option:");
        println!("0. List encrypted passwords and secrets");
        println!("1. List passwords and secrets");
        println!("2. Add a new password/secret");
        println!("3. Delete a password/secret");
        println!("4. Import passwords from file");
        println!("5. Exit");
        let mut input = String::new();
        stdin.read_line(&mut input).expect("Failed to read line");
        let input = input.trim();
        match input {
            "0" => {
                println!("Writing unencrypted passwords to file...");
                let passwords_path = get_passwords_file_path();
                let mut file = File::create(&passwords_path).expect("Unable to create file");
                for (identifier, encrypted_password) in &password_map {
                    let enc_base64 = general_purpose::STANDARD_NO_PAD
                        .encode(encrypted_password.password.data.as_slice());
                    let nonce_str = encrypted_password
                        .password
                        .nonce
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>(); // convert to hex string
                    let line = format!(
                        "{}: {}: {}: {}: {}\n",
                        identifier,
                        encrypted_password.id,
                        encrypted_password.username,
                        enc_base64,
                        nonce_str
                    );
                    file.write_all(line.as_bytes())
                        .expect("Unable to write data");
                }
            }
            "1" => {
                if password_map.is_empty() {
                    println!("No passwords found.\n");
                    continue;
                }
                println!("Listing passwords...");
                for (identifier, encrypted_password) in &password_map {
                    let password = decrypt(encrypted_password.password.clone(), &key);
                    // when there is a error in decrypting, the master password was unsolicitedly changed. in this case, delete all passwords and exit
                    println!("{}({}): {} {}", identifier, encrypted_password.id, encrypted_password.username, String::from_utf8(password).unwrap_or_else(|_| {
                        delete_password_files().ok();
                        println!("Unsolicited change of master password detected. All passwords including the Masterpassword have been deleted. Please restart the program.");
                        std::process::exit(0);
                    }));
                }
            }
            "2" => {
                println!("Enter identifier:");
                let mut identifier = String::new();
                stdin
                    .read_line(&mut identifier)
                    .expect("Failed to read identifier");
                let identifier = identifier.trim().to_string();

                println!("Enter username:");
                let mut username = String::new();
                stdin
                    .read_line(&mut username)
                    .expect("Failed to read username");
                let username = username.trim().to_string();

                println!("Enter password:");
                let mut password = String::new();
                stdin
                    .read_line(&mut password)
                    .expect("Failed to read password");
                let password = password.trim().as_bytes().to_vec();
                let encrypted_password = encrypt(&password, &key);
                password_map.insert(
                    identifier,
                    Password {
                        id: determine_id(&password_map),
                        username,
                        password: encrypted_password,
                    },
                );
            }
            "3" => {
                println!("Enter identifier to delete:");
                let mut identifier = String::new();
                stdin
                    .read_line(&mut identifier)
                    .expect("Failed to read identifier");
                let identifier = identifier.trim().to_string();

                if password_map.remove(&identifier).is_some() {
                    println!("Deleted password for {}", identifier);
                } else {
                    println!("No password found for {}", identifier);
                }
            }
            "4" => {
                println!("Reading passwords from file...");
                let passwords_path = get_passwords_file_path();
                let mut file = File::open(&passwords_path).expect("file not found");
                let mut contents = String::new();
                file.read_to_string(&mut contents)
                    .expect("something went wrong reading the file");
                let lines = contents.split("\n");
                for line in lines {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let mut split = line.split(": ");
                    let identifier = split.next().unwrap();
                    let id = split.next().unwrap();
                    let username = split.next().unwrap();
                    let password = split.next().unwrap();
                    let nonce = split.next().unwrap();
                    let password = password.trim();
                    let nonce = nonce.trim();
                    let password = general_purpose::STANDARD_NO_PAD
                        .decode(password.as_bytes())
                        .unwrap();
                    let nonce = hex::decode(nonce).unwrap();
                    let encrypted_password = Block {
                        data: password,
                        nonce,
                    };
                    password_map.insert(
                        identifier.to_string(),
                        Password {
                            id: id.parse::<u32>().unwrap(),
                            username: username.to_string(),
                            password: encrypted_password,
                        },
                    );
                }
            }
            "5" => {
                println!("Goodbye!");
                return;
            }
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
