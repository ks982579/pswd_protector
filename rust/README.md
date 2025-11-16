# pswdstore

A secure, PIN-protected command-line password manager built in Rust.

## Features

- **🔒 Secure Encryption**: AES-256-GCM encryption with PIN-based key derivation
- **📝 Interactive Entry**: User-friendly prompts for password creation
- **🔍 Fast Search**: Search passwords by domain, username, or email
- **📊 Audit Trail**: Comprehensive logging of all operations with timestamps
- **💾 Portable Storage**: Single encrypted JSON file for easy backup
- **🛡️ Double Verification**: Decryption + hash verification for extra security

## Installation

### Easy Installation (Linux)

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd pswd_protector/rust
   ```

2. Run the installer:
   ```bash
   ./install.sh
   ```

The installer will:

- Build the project in release mode
- Install the binary to `~/.local/bin/pswdstore`
- Test the installation
- Provide setup instructions if PATH configuration is needed

### Manual Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd pswd_protector/rust
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

3. Copy to your bin directory:
   ```bash
   cp target/release/pswdstore ~/.local/bin/
   # or
   sudo cp target/release/pswdstore /usr/local/bin/
   ```

## Usage

### Initialize Password Store

First, create your encrypted password store with a PIN:

```bash
pswdstore --init
```

You'll be prompted to enter your PIN (input will be masked for security). This creates an encrypted file at `~/.pswdstore.json`.

### Add a New Password

```bash
pswdstore --new
```

You'll be prompted for your PIN first (masked input), then interactively for:

- Domain (e.g., "github.com")
- Username
- Password (with confirmation)
- Email (optional)
- Security questions (optional, multiple allowed)

Example session:

```
Creating new password entry...

Domain (e.g., github.com): github.com
Username: john_doe
Password: [hidden]
Confirm password: [hidden]
Add email address? (y/n): y
Email: john@example.com
Add a security question? (y/n): y
Security question: What was your first pet's name?
Answer: Fluffy
Add a security question? (y/n): n

✓ Password entry saved for github.com successfully!
```

### Search for Passwords (Interactive Mode)

```bash
pswdstore --get github
```

You'll be prompted to enter your PIN first (masked input).

**Single match** - goes directly to interaction menu:

```
What would you like to do with github.com?
❯ Copy password to clipboard
  Show password (will be visible)
  Show security questions
  Back to search results
```

**Multiple matches** - choose which account:

```
Found 2 matching entries:

1. nelnet.com (mom_account)
2. nelnet.com (my_account)

? Select an entry to interact with ›
```

### List Passwords (Safe Display)

```bash
pswdstore --list github
```

Example output:

```
Found 1 matching entry:

Domain: github.com
Username: john_doe
Password: [HIDDEN - use interactive mode to reveal]
Email: john@example.com
Security Questions: 1 question(s) stored
```

**List all entries:**

```bash
pswdstore --list
```

### Update Password Entries

```bash
pswdstore --update github
```

**Single match** - goes directly to update options:

```
What would you like to update for john_doe (github.com)?
❯ Update password
  Update email
  Update security questions
  Cancel
```

**Multiple matches** - choose which account to update:

```
Found 2 matching entries:
1. personal_account (github.com)
2. work_account (github.com)

? Select entry to update ›
```

**Update options:**

- **Password**: Secure password change with confirmation
- **Email**: Add, change, or remove email address
- **Security Questions**: Add new, replace all, or remove all

### Delete Password Entries

```bash
pswdstore --destroy github
```

**Selection and confirmation process:**

```
Found 2 matching entries:
1. personal_account for github.com
2. work_account for github.com

? Select entry to delete ›

⚠️  You are about to delete:
Domain: github.com
Username: personal_account
Email: john@personal.com
Security Questions: 2

🚨 This action is PERMANENT and CANNOT be undone!
? Are you absolutely sure you want to delete this entry? (y/n) ›
```

Search terms match against:

- Domain names
- Usernames
- Email addresses

## Security

### Encryption Details

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: SHA-256 with salt
- **PIN Storage**: SHA-256 hash (never stored in plaintext)
- **Nonce**: Randomly generated for each encryption operation

### Security Features

1. **Double Verification**: Both decryption success AND PIN hash verification must pass
2. **No Plaintext Storage**: All sensitive data encrypted at rest
3. **Secure Key Derivation**: PIN combined with salt for key generation
4. **Audit Trail**: All operations logged with user and timestamp
5. **Memory Safety**: Built in Rust for memory-safe operations
6. **Terminal History Protection**: Passwords never displayed unless explicitly requested
7. **Clipboard Integration**: Secure password copying without terminal exposure
8. **Interactive Security**: Multiple confirmation steps for password revelation

### Wrong PIN Protection

If an incorrect PIN is provided:

- Decryption will fail with "Decryption failed - invalid PIN"
- Even if somehow decrypted, PIN hash verification will fail
- No sensitive data is exposed

## Data Structure

The encrypted JSON file contains:

```json
{
  "logs": {
    "created": {
      "action": "created",
      "datetime": "2024-01-01T12:00:00Z",
      "user": "username"
    },
    "pin_hash": "sha256_hash_of_pin",
    "updated": [
      {
        "action": "new",
        "datetime": "2024-01-01T12:30:00Z",
        "user": "username"
      }
    ]
  },
  "data": [
    {
      "domain": "github.com",
      "username": "john_doe",
      "password": "mySecurePassword123!",
      "email": "john@example.com",
      "security_questions": [
        {
          "question": "What was your first pet's name?",
          "answer": "Fluffy"
        }
      ]
    }
  ]
}
```

## Command Reference

| Command                         | Description                                                           |
| ------------------------------- | --------------------------------------------------------------------- |
| `pswdstore --init`              | Initialize new password store (prompts for PIN)                       |
| `pswdstore --new`               | Add new password entry (prompts for PIN, then interactive)            |
| `pswdstore --get <term>`        | Search for passwords (prompts for PIN, interactive mode)              |
| `pswdstore --list [term]`       | List passwords safely (prompts for PIN, passwords hidden)             |
| `pswdstore --update <term>`     | Update existing password entry (prompts for PIN)                      |
| `pswdstore --destroy <term>`    | Delete password entry (prompts for PIN, with confirmation)            |
| `pswdstore --help`              | Show help information                                                 |
| `pswdstore --version`           | Show version information                                              |

## Examples

### Complete Workflow

```bash
# 1. Initialize store
$ pswdstore --init
Enter PIN: ****
✓ Password store initialized successfully!

# 2. Add a password
$ pswdstore --new
Enter PIN: ****
Creating new password entry...
Domain (e.g., github.com): gmail.com
Username: john.doe@gmail.com
Password: [hidden]
Confirm password: [hidden]
Add email address? (y/n): n
Add a security question? (y/n): y
Security question: Mother's maiden name?
Answer: Smith
Add a security question? (y/n): n
✓ Password entry saved for gmail.com successfully!

# 3. Search for passwords (interactive)
$ pswdstore --get gmail
Enter PIN: ****
What would you like to do with gmail.com?
❯ Copy password to clipboard
  Show password (will be visible)
  Show security questions
  Back to search results

# 4. List passwords safely
$ pswdstore --list gmail
Enter PIN: ****
Found 1 matching entry:

Domain: gmail.com
Username: john.doe@gmail.com
Password: [HIDDEN - use interactive mode to reveal]
Security Questions: 1 question(s) stored

# 5. Handle multiple accounts
$ pswdstore --get nelnet
Enter PIN: ****
Found 2 matching entries:

1. nelnet.com (mom_account)
2. nelnet.com (my_account)

? Select an entry to interact with ›

# 6. Update a password
$ pswdstore --update gmail
Enter PIN: ****
What would you like to update for john.doe@gmail.com (gmail.com)?
❯ Update password
  Update email
  Update security questions
  Cancel

# 7. Delete an entry (careful!)
$ pswdstore --destroy old-site
Enter PIN: ****
⚠️  You are about to delete:
Domain: old-site.com
Username: old_user
🚨 This action is PERMANENT and CANNOT be undone!
? Are you absolutely sure you want to delete this entry? (y/n) › y
✓ Deleted entry for old_user (old-site.com)
```

## File Location

The encrypted password store is saved as:

- **Linux/macOS**: `~/.pswdstore.json`
- **Windows**: `%USERPROFILE%\.pswdstore.json`

## Backup and Recovery

Since all data is stored in a single encrypted file:

1. **Backup**: Copy `~/.pswdstore.json` to secure location
2. **Restore**: Copy the file back and use with your PIN
3. **Transfer**: Move the file to another machine and access with same PIN

## Development

### Dependencies

- `clap` - Command line argument parsing
- `dialoguer` - Interactive prompts
- `serde` + `serde_json` - JSON serialization
- `aes-gcm` - AES-256-GCM encryption
- `sha2` - SHA-256 hashing
- `base64` - Base64 encoding
- `chrono` - Date/time handling
- `whoami` - User information
- `dirs` - Directory utilities
- `arboard` - Secure clipboard integration

### Building

```bash
cargo build --release
```

### Testing

```bash
cargo test
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Security Considerations

- **PIN Strength**: Use a strong, unique PIN
- **File Permissions**: Ensure `~/.pswdstore.json` has appropriate permissions
- **Backup Security**: Store backups securely
- **PIN Security**: Never share your PIN or store it insecurely
- **Regular Updates**: Keep the tool updated for security patches

## Troubleshooting

### Common Issues

**"Password store not found"**

- Run `pswdstore --init` first

**"Invalid PIN"**

- Check your PIN is correct
- Ensure caps lock is not on

**"Permission denied"**

- Check file permissions on `~/.pswdstore.json`
- Ensure you have write access to home directory

**"Decryption failed"**

- PIN is incorrect
- File may be corrupted (restore from backup)

---

## Credits

This password manager was developed with assistance from Claude (Anthropic's AI assistant), providing architecture design, security implementation, and comprehensive documentation. The project demonstrates secure Rust development practices and modern CLI design patterns.
