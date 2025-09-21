use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use clap::{Arg, Command};
use dialoguer::{Input, Password, Confirm};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SecurityQuestion {
    question: String,
    answer: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PasswordEntry {
    domain: String,
    username: String,
    password: String,
    email: Option<String>,
    security_questions: Vec<SecurityQuestion>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct LogEntry {
    action: String,
    datetime: DateTime<Utc>,
    user: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Metadata {
    created: LogEntry,
    pin_hash: String,
    updated: Vec<LogEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PasswordStore {
    logs: Metadata,
    data: Vec<PasswordEntry>,
}

impl PasswordStore {
    fn new(pin: &str) -> Self {
        let user = whoami::username();
        let created_log = LogEntry {
            action: "created".to_string(),
            datetime: Utc::now(),
            user,
        };
        
        Self {
            logs: Metadata {
                created: created_log,
                pin_hash: hash_pin(pin),
                updated: Vec::new(),
            },
            data: Vec::new(),
        }
    }

    fn add_entry(&mut self, entry: PasswordEntry) {
        self.data.push(entry);
        self.logs.updated.push(LogEntry {
            action: "new".to_string(),
            datetime: Utc::now(),
            user: whoami::username(),
        });
    }

    fn save_encrypted(&self, path: &PathBuf, pin: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        let encrypted_data = encrypt_data(&json, pin)?;
        fs::write(path, encrypted_data)?;
        Ok(())
    }

    fn load_encrypted(path: &PathBuf, pin: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if !path.exists() {
            return Err("Password store not found. Run 'pswdstore <pin> --init' first.".into());
        }
        
        let encrypted_content = fs::read_to_string(path)?;
        let decrypted_json = decrypt_data(&encrypted_content, pin)?;
        let store: PasswordStore = serde_json::from_str(&decrypted_json)
            .map_err(|_| "Invalid PIN or corrupted data")?;
        
        if !verify_pin(&store.logs.pin_hash, pin) {
            return Err("Invalid PIN".into());
        }
        
        Ok(store)
    }

    fn find_entries(&self, search_term: &str) -> Vec<&PasswordEntry> {
        self.data.iter()
            .filter(|entry| {
                entry.domain.to_lowercase().contains(&search_term.to_lowercase()) ||
                entry.username.to_lowercase().contains(&search_term.to_lowercase()) ||
                entry.email.as_ref().map_or(false, |email| 
                    email.to_lowercase().contains(&search_term.to_lowercase()))
            })
            .collect()
    }
}

fn hash_pin(pin: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pin.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn verify_pin(hash: &str, pin: &str) -> bool {
    hash_pin(pin) == hash
}

fn derive_key_from_pin(pin: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pin.as_bytes());
    hasher.update(b"pswdstore-salt");
    hasher.finalize().into()
}

fn encrypt_data(data: &str, pin: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key_bytes = derive_key_from_pin(pin);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    let ciphertext = cipher.encrypt(&nonce, data.as_bytes())
        .map_err(|_| "Encryption failed")?;
    
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(general_purpose::STANDARD.encode(result))
}

fn decrypt_data(encrypted_data: &str, pin: &str) -> Result<String, Box<dyn std::error::Error>> {
    let data = general_purpose::STANDARD.decode(encrypted_data)
        .map_err(|_| "Invalid encrypted data format")?;
    
    if data.len() < 12 {
        return Err("Invalid encrypted data".into());
    }
    
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let key_bytes = derive_key_from_pin(pin);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed - invalid PIN")?;
    
    String::from_utf8(plaintext)
        .map_err(|_| "Invalid UTF-8 in decrypted data".into())
}

fn get_storage_path() -> PathBuf {
    let home_dir = dirs::home_dir().expect("Could not find home directory");
    home_dir.join(".pswdstore.json")
}

fn interactive_new_entry() -> Result<PasswordEntry, Box<dyn std::error::Error>> {
    println!("Creating new password entry...\n");

    let domain: String = Input::new()
        .with_prompt("Domain (e.g., github.com)")
        .interact_text()?;

    let username: String = Input::new()
        .with_prompt("Username")
        .interact_text()?;

    let password: String = Password::new()
        .with_prompt("Password")
        .with_confirmation("Confirm password", "Passwords don't match")
        .interact()?;

    let email: Option<String> = if Confirm::new()
        .with_prompt("Add email address?")
        .interact()? 
    {
        Some(Input::new()
            .with_prompt("Email")
            .interact_text()?)
    } else {
        None
    };

    let mut security_questions = Vec::new();
    
    while Confirm::new()
        .with_prompt("Add a security question?")
        .interact()? 
    {
        let question: String = Input::new()
            .with_prompt("Security question")
            .interact_text()?;

        let answer: String = Input::new()
            .with_prompt("Answer")
            .interact_text()?;

        security_questions.push(SecurityQuestion { question, answer });
    }

    Ok(PasswordEntry {
        domain,
        username,
        password,
        email,
        security_questions,
    })
}

fn display_entry(entry: &PasswordEntry) {
    println!("Domain: {}", entry.domain);
    println!("Username: {}", entry.username);
    println!("Password: {}", entry.password);
    
    if let Some(email) = &entry.email {
        println!("Email: {}", email);
    }
    
    if !entry.security_questions.is_empty() {
        println!("Security Questions:");
        for (i, sq) in entry.security_questions.iter().enumerate() {
            println!("  {}. Q: {}", i + 1, sq.question);
            println!("     A: {}", sq.answer);
        }
    }
    println!();
}

fn main() {
    let matches = Command::new("pswdstore")
        .version("0.1.0")
        .about("A PIN-secured CLI password storage tool")
        .arg(
            Arg::new("pin")
                .help("PIN to access the password store")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("init")
                .long("init")
                .help("Initialize a new password store")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("new")
                .long("new")
                .help("Create a new password entry")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("get")
                .long("get")
                .help("Search for password entries")
                .value_name("SEARCH_TERM")
                .num_args(1),
        )
        .get_matches();

    let pin = matches.get_one::<String>("pin").unwrap();
    let storage_path = get_storage_path();

    if matches.get_flag("init") {
        if storage_path.exists() {
            eprintln!("Password store already exists at {}", storage_path.display());
            eprintln!("Remove the existing file if you want to reinitialize.");
            return;
        }
        
        let store = PasswordStore::new(pin);
        match store.save_encrypted(&storage_path, pin) {
            Ok(_) => println!("✓ Password store initialized successfully!"),
            Err(e) => eprintln!("Error initializing password store: {}", e),
        }
        return;
    }

    let mut store = match PasswordStore::load_encrypted(&storage_path, pin) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    if matches.get_flag("new") {
        match interactive_new_entry() {
            Ok(entry) => {
                store.add_entry(entry.clone());
                
                match store.save_encrypted(&storage_path, pin) {
                    Ok(_) => println!("\n✓ Password entry saved for {} successfully!", entry.domain),
                    Err(e) => eprintln!("Error saving password entry: {}", e),
                }
            }
            Err(e) => eprintln!("Error creating password entry: {}", e),
        }
    } else if let Some(search_term) = matches.get_one::<String>("get") {
        let results = store.find_entries(search_term);
        
        if results.is_empty() {
            println!("No entries found matching '{}'", search_term);
        } else {
            println!("Found {} matching entr{}:", 
                results.len(), 
                if results.len() == 1 { "y" } else { "ies" }
            );
            println!();
            
            for entry in results {
                display_entry(entry);
            }
        }
    } else {
        println!("Use --help to see available commands");
    }
}
