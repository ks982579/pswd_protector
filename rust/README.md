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
pswdstore 1234 --init
```

This creates an encrypted file at `~/.pswdstore.json`.

### Add a New Password

```bash
pswdstore 1234 --new
```

You'll be prompted interactively for:
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

### Search for Passwords

```bash
pswdstore 1234 --get github
```

Example output:
```
Found 1 matching entry:

Domain: github.com
Username: john_doe
Password: mySecurePassword123!
Email: john@example.com
Security Questions:
  1. Q: What was your first pet's name?
     A: Fluffy
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

| Command | Description |
|---------|-------------|
| `pswdstore <pin> --init` | Initialize new password store |
| `pswdstore <pin> --new` | Add new password entry (interactive) |
| `pswdstore <pin> --get <term>` | Search for passwords matching term |
| `pswdstore --help` | Show help information |
| `pswdstore --version` | Show version information |

## Examples

### Complete Workflow

```bash
# 1. Initialize store
$ pswdstore mypin123 --init
✓ Password store initialized successfully!

# 2. Add a password
$ pswdstore mypin123 --new
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

# 3. Search for passwords
$ pswdstore mypin123 --get gmail
Found 1 matching entry:

Domain: gmail.com
Username: john.doe@gmail.com
Password: secretPassword456!
Security Questions:
  1. Q: Mother's maiden name?
     A: Smith

# 4. Search by username
$ pswdstore mypin123 --get john.doe
Found 1 matching entry:
[same output as above]
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
- Run `pswdstore <pin> --init` first

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