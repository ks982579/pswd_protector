# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-01-01

### Added
- Initial release of pswdstore CLI password manager
- PIN-based AES-256-GCM encryption for secure password storage
- Interactive password entry with confirmation
- Support for optional email addresses
- Multiple security questions per entry
- Search functionality across domains, usernames, and emails
- Comprehensive audit logging with timestamps and user tracking
- Encrypted JSON file storage in user home directory
- Command-line interface with clap argument parsing
- User-friendly interactive prompts with dialoguer
- Automatic password store initialization
- Double PIN verification (decryption + hash check)
- SHA-256 PIN hashing with salt
- Base64 encoding for encrypted data storage
- Cross-platform support (Linux, macOS, Windows)

### Security Features
- AES-256-GCM encryption with randomly generated nonces
- PIN-derived encryption keys using SHA-256 with salt
- No plaintext storage of sensitive data
- Memory-safe implementation in Rust
- Secure key derivation preventing rainbow table attacks
- Audit trail for all operations

### Commands
- `pswdstore <pin> --init` - Initialize new encrypted password store
- `pswdstore <pin> --new` - Create new password entry interactively
- `pswdstore <pin> --get <search_term>` - Search and display matching passwords
- `pswdstore --help` - Display help information
- `pswdstore --version` - Show version information

### Dependencies
- clap 4.4 - Command line argument parsing
- dialoguer 0.11 - Interactive terminal prompts
- serde 1.0 + serde_json 1.0 - JSON serialization
- aes-gcm 0.10 - AES-256-GCM encryption
- sha2 0.10 - SHA-256 hashing
- base64 0.22 - Base64 encoding/decoding
- chrono 0.4 - Date and time handling
- whoami 1.4 - System user information
- dirs 5.0 - Cross-platform directory utilities

### Data Structure
- Structured JSON format with metadata and data sections
- Creation and update logs with user attribution
- Flexible password entry schema supporting optional fields
- Support for multiple security questions per entry
- PIN hash storage for verification
- Timestamp tracking for all operations

### Technical Details
- Rust 2021 edition
- Memory-safe password handling
- Encrypted file storage at `~/.pswdstore.json`
- Case-insensitive search functionality
- Interactive confirmation for password entry
- Graceful error handling and user feedback
- Cross-platform compatibility

## [0.1.1] - 2025-01-21

### 🔒 Security (Critical Fix)
- **FIXED**: Critical security vulnerability where passwords were displayed in terminal output
- **FIXED**: Passwords no longer stored in terminal history or system logs
- **ADDED**: Terminal history protection - passwords never displayed unless explicitly requested

### Added
- Interactive password access with secure options:
  - Copy to clipboard (most secure option)
  - Show password with explicit warning and confirmation
  - Show security questions separately
- New `--list` command for safe password browsing with hidden passwords
- Enhanced `--get` command with interactive selection for multiple matches
- Clipboard integration for secure password copying
- Multi-step confirmation for password revelation
- Better handling of multiple accounts for same domain

### Changed
- Password display behavior completely redesigned for security
- Search results now show entries safely with passwords hidden by default
- Interactive menus for password access instead of direct terminal output
- Improved user experience for multiple matching entries

### Security Enhancements
- Passwords displayed as `[HIDDEN - use interactive mode to reveal]` in listings
- Explicit warnings before showing passwords on screen
- Secure clipboard copying as primary access method
- Prevention of accidental password exposure in terminal scrollback
- Interactive confirmation required for any password visibility

### Dependencies
- **ADDED**: `arboard` 3.2 for secure clipboard functionality

## [0.1.2] - 2025-01-21

### Added
- **Update functionality** (`--update <search>`) for modifying existing password entries
  - Interactive field selection: password, email, or security questions
  - Secure password updates with confirmation prompts
  - Email management: add, change, or remove email addresses
  - Security questions management: add new, replace all, or remove all
  - Multiple account support with clear username/domain identification
- **Delete functionality** (`--destroy <search>`) for removing password entries
  - Interactive entry selection for multiple matches
  - Comprehensive entry preview before deletion
  - Multi-step confirmation process with permanent action warnings
  - Safe cancellation at any point in the process
- Enhanced audit logging for all update and delete operations
- Improved user experience with detailed confirmation prompts

### Changed
- Entry selection now displays as "username (domain)" for updates
- Entry selection displays as "username for domain" for deletions
- Enhanced error handling and user feedback for all operations

### Security Enhancements
- All update operations require explicit confirmation
- Delete operations include multiple safety confirmations
- Permanent action warnings prevent accidental data loss
- Full audit trail for all modifications and deletions

### Technical Improvements
- Added `update_entry()` and `delete_entry()` methods to PasswordStore
- Implemented comprehensive search and selection logic
- Enhanced interactive prompts for better user experience
- Automatic data persistence after all modifications

## [Unreleased]

### Planned Features
- Import/export features
- Password generation utilities
- Backup and restore commands
- Configuration file support
- Multiple password store support
- Password strength analysis
- Bulk operations
- CLI scripting support

### Security Enhancements (Planned)
- Optional two-factor authentication
- Password expiration tracking
- Breach detection integration
- Enhanced key derivation options
- Hardware security module support
- Encrypted backup functionality

---

## Version History Summary

| Version | Date | Description |
|---------|------|-------------|
| 0.1.2 | 2025-01-21 | Added update and delete functionality with enhanced security |
| 0.1.1 | 2025-01-21 | Critical security fix: terminal history protection |
| 0.1.0 | 2024-01-01 | Initial release with core password storage and encryption |

---

## Release Notes

### Version 0.1.2

This release completes the core password management functionality by adding comprehensive **update** and **delete** capabilities with enhanced security measures.

**🔧 New Features:**
- **Password Entry Updates**: Modify passwords, emails, and security questions on existing entries
- **Safe Entry Deletion**: Remove password entries with multiple confirmation steps
- **Multiple Account Support**: Handle multiple accounts per domain with clear identification
- **Interactive Field Selection**: Choose exactly what to update without affecting other fields

**🛡️ Security Enhancements:**
- **Confirmation Prompts**: All updates require explicit confirmation
- **Permanent Action Warnings**: Delete operations include clear warnings about data loss
- **Audit Trail**: All modifications and deletions are logged with timestamps
- **Safe Cancellation**: Users can cancel operations at any point

**📋 Use Cases:**
- **Password Changes**: Easily update passwords when they expire or are compromised
- **Account Cleanup**: Remove old or unused accounts safely
- **Information Updates**: Modify email addresses and security questions as needed
- **Multiple Accounts**: Manage multiple accounts per domain (e.g., personal and work GitHub accounts)

**🎯 Perfect For:**
- Regular password rotation and security maintenance
- Cleaning up old accounts and services
- Managing complex account structures with multiple logins per service

### Version 0.1.1

This is a **critical security update** that addresses a significant vulnerability in password display behavior. **All users should upgrade immediately.**

**🚨 Security Fix:**
- Resolved critical issue where passwords were displayed directly in terminal output
- Eliminated risk of passwords being stored in terminal history, system logs, or scrollback buffers
- Implemented comprehensive terminal history protection

**🔧 Improvements:**
- Added secure clipboard integration for password access
- Introduced interactive password handling with explicit user confirmation
- Enhanced support for multiple accounts per domain
- Improved overall user experience with safer default behaviors

**📋 New Commands:**
- `--list`: Browse passwords safely with sensitive data hidden
- Enhanced `--get`: Interactive mode with clipboard copying and secure reveal options

**⚠️ Breaking Changes:**
None - all existing commands work the same, but with improved security.

**🔄 Migration:**
No migration needed. Existing password stores work unchanged with enhanced security.

### Version 0.1.0

This is the initial release of pswdstore, a secure CLI password manager built in Rust. The focus of this release was establishing a solid foundation for password storage with strong encryption and a user-friendly interface.

**Key Highlights:**
- Military-grade AES-256-GCM encryption
- Interactive password entry process
- Comprehensive search capabilities
- Full audit trail for security compliance
- Cross-platform compatibility
- Single encrypted file storage for portability

**Security Focus:**
This release prioritizes security with multiple layers of protection including encryption, PIN hashing, and verification. The tool is designed to be both secure and user-friendly for daily password management needs.

**Getting Started:**
1. Initialize your password store: `pswdstore <pin> --init`
2. Add your first password: `pswdstore <pin> --new`
3. Search for passwords: `pswdstore <pin> --get <term>`

For detailed documentation, see [README.md](README.md).

---

## Contributing to Changelog

When contributing changes, please:
1. Add entries under the `[Unreleased]` section
2. Follow the format: `### Category` followed by `- Description`
3. Use categories: Added, Changed, Deprecated, Removed, Fixed, Security
4. Move items from Unreleased to a new version section when releasing
5. Include the date in ISO format (YYYY-MM-DD)
6. Add a link to compare versions at the bottom when creating releases