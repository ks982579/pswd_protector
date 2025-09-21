use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use arboard::Clipboard;
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use clap::{Arg, Command};
use dialoguer::{Input, Password, Confirm, Select};
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

fn display_entry_safely(entry: &PasswordEntry) {
    println!("Domain: {}", entry.domain);
    println!("Username: {}", entry.username);
    println!("Password: [HIDDEN - use interactive mode to reveal]");
    
    if let Some(email) = &entry.email {
        println!("Email: {}", email);
    }
    
    if !entry.security_questions.is_empty() {
        println!("Security Questions: {} question(s) stored", entry.security_questions.len());
    }
    println!();
}

fn handle_entry_interaction(entry: &PasswordEntry) -> Result<(), Box<dyn std::error::Error>> {
    let options = vec![
        "Copy password to clipboard",
        "Show password (will be visible)",
        "Show security questions",
        "Back to search results"
    ];
    
    loop {
        let selection = Select::new()
            .with_prompt(&format!("What would you like to do with {}?", entry.domain))
            .items(&options)
            .default(0)
            .interact()?;
        
        match selection {
            0 => {
                match Clipboard::new() {
                    Ok(mut clipboard) => {
                        match clipboard.set_text(&entry.password) {
                            Ok(_) => {
                                println!("✓ Password copied to clipboard!");
                                println!("⚠️  Remember to clear clipboard when done");
                            }
                            Err(_) => println!("✗ Failed to copy to clipboard")
                        }
                    }
                    Err(_) => println!("✗ Clipboard not available on this system")
                }
            }
            1 => {
                println!("\n⚠️  PASSWORD WILL BE VISIBLE ON SCREEN!");
                if Confirm::new().with_prompt("Continue?").interact()? {
                    println!("Password: {}", entry.password);
                    println!("Press Enter to continue...");
                    std::io::stdin().read_line(&mut String::new())?;
                }
            }
            2 => {
                if entry.security_questions.is_empty() {
                    println!("No security questions stored for this entry.");
                } else {
                    println!("\nSecurity Questions:");
                    for (i, sq) in entry.security_questions.iter().enumerate() {
                        println!("  {}. Q: {}", i + 1, sq.question);
                        println!("     A: {}", sq.answer);
                    }
                    println!("Press Enter to continue...");
                    std::io::stdin().read_line(&mut String::new())?;
                }
            }
            3 => break,
            _ => {}
        }
        println!(); // Add spacing
    }
    
    Ok(())
}

fn main() {
    let matches = Command::new("pswdstore")
        .version("0.1.1")
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
                .help("Search for password entries (interactive mode)")
                .value_name("SEARCH_TERM")
                .num_args(1),
        )
        .arg(
            Arg::new("list")
                .long("list")
                .help("List password entries (safe display)")
                .value_name("SEARCH_TERM")
                .num_args(0..=1),
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
        } else if results.len() == 1 {
            // Single result - go directly to interaction
            match handle_entry_interaction(results[0]) {
                Ok(_) => {},
                Err(e) => eprintln!("Error: {}", e),
            }
        } else {
            // Multiple results - let user choose
            println!("Found {} matching entries:", results.len());
            println!();
            
            for (i, entry) in results.iter().enumerate() {
                println!("{}. {} ({})", i + 1, entry.domain, entry.username);
            }
            
            let selection = Select::new()
                .with_prompt("Select an entry to interact with")
                .items(&results.iter().map(|e| format!("{} ({})", e.domain, e.username)).collect::<Vec<_>>())
                .interact();
            
            match selection {
                Ok(index) => {
                    match handle_entry_interaction(results[index]) {
                        Ok(_) => {},
                        Err(e) => eprintln!("Error: {}", e),
                    }
                }
                Err(e) => eprintln!("Selection error: {}", e),
            }
        }
    } else if let Some(search_term) = matches.get_one::<String>("list") {
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
                display_entry_safely(entry);
            }
        }
    } else if matches.get_flag("list") {
        // List all entries safely
        if store.data.is_empty() {
            println!("No password entries found.");
        } else {
            println!("All password entries ({} total):", store.data.len());
            println!();
            
            for entry in &store.data {
                display_entry_safely(entry);
            }
        }
    } else {
        println!("Use --help to see available commands");
    }
}
