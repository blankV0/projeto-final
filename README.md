# Educational Password Manager

A comprehensive Python CLI application demonstrating secure password management practices. This project is designed for **educational purposes** to teach fundamental concepts of password security, hashing, and cryptography.

## ⚠️ Critical Security Warning

**MD5 and MD4 are cryptographically BROKEN and must NEVER be used for real password storage!**

This implementation uses obsolete hashing algorithms **intentionally** for educational purposes to demonstrate concepts of password security, hashing vs encryption, and why passwords should never be stored in plaintext.

### What Production Systems Must Use

- **bcrypt**: Industry standard, adaptive cost, built-in salt
- **scrypt**: Memory-hard, resistant to hardware attacks  
- **Argon2**: Modern, winner of Password Hashing Competition

## 🎓 Learning Objectives

1. **Password Storage**: Why passwords must NEVER be stored in plaintext
2. **Hashing vs. Encryption**: Understanding one-way vs two-way transformations
3. **Salting**: How to prevent rainbow table attacks
4. **Password Generation**: Cryptographically secure random passwords
5. **Modern Practices**: Input validation, error handling, code structure

## 📁 Project Structure

```
projeto-final/
├── password_manager.py      # Main CLI application
├── gui.py                   # Tkinter GUI application
├── password_generator.py    # Secure password generation
├── database.py              # SQLite database operations
├── hash_utils.py            # Password hashing (MD5/MD4)
├── word_manager.py          # Legacy word hash manager
├── test_word_manager.py     # Test suite (pytest)
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/blankV0/projeto-final.git
cd projeto-final
pip3 install -r requirements.txt
```

### Usage Examples

```bash
# Generate a strong password
python3 password_manager.py generate

# Add entry with generated password
python3 password_manager.py add Gmail user@example.com --generate

# List all entries (passwords never shown)
python3 password_manager.py list

# Verify a password
python3 password_manager.py verify Gmail user@example.com

# For more help
python3 password_manager.py --help
```

### Launching the GUI

```bash
# Start the graphical user interface
python3 gui.py
```

**GUI Features:**

The modern GUI includes:
1. **Add Entry**: Create new password entries with automatic password strength validation
2. **List Entries**: View all stored entries (passwords never shown)
3. **Verify Password**: Check if a password matches stored hash (with secure comparison)
4. **Edit Entry**: Modify service names and usernames
5. **Change Password**: Update passwords with current password verification
6. **Generate Password**: Create strong random passwords with customizable options
7. **Action Logs**: Monitor all activities (passwords never logged)

**Security Features:**
- ✅ Automatic unique salt generation for each entry
- ✅ Password strength validation (min 8 chars, letters, numbers, symbols)
- ✅ Weak password warnings with option to continue
- ✅ Secure hash comparison using `hmac.compare_digest` (timing-attack resistant)
- ✅ Comprehensive action logging without exposing passwords

**Why a GUI?**

The GUI was added on top of the CLI to:
1. **Improve Accessibility**: Provide a user-friendly interface for users who prefer graphical interaction
2. **Educational Value**: Demonstrate how to build a GUI that reuses existing business logic modules
3. **Visual Learning**: Make it easier to understand password management concepts through visual feedback
4. **Best Practices**: Show proper separation of concerns (GUI vs. business logic)

The GUI reuses the same modules as the CLI (`database.py`, `hash_utils.py`, `password_generator.py`) without duplicating any business logic.

## 📖 Full Documentation

See complete documentation sections below:
- How It Works
- Database Schema
- Hashing vs Encryption
- Security Concepts
- Testing Guide
- Future Improvements

## 🔬 How It Works

### Password Storage Flow
```
User enters password → Hash with MD5/MD4 → Store ONLY hash → Discard password
```

### Password Verification Flow
```
User enters password → Hash with same algorithm → Compare hashes → Match = correct
```

### Database Schema
```sql
CREATE TABLE passwords (
    id INTEGER PRIMARY KEY,
    service TEXT NOT NULL,        -- Service name
    username TEXT NOT NULL,       -- Username
    password_hash TEXT NOT NULL,  -- NEVER plaintext
    algorithm TEXT NOT NULL,      -- 'md5' or 'md4'
    salt TEXT,                    -- Unique salt per entry
    created_at TIMESTAMP,
    UNIQUE(service, username)
);
```

## 🎯 Key Educational Concepts

### 1. Hashing vs. Encryption

| Aspect | Hashing | Encryption |
|--------|---------|------------|
| Direction | One-way | Two-way |
| Purpose | Passwords, integrity | Confidential data |
| Reversible | No | Yes (with key) |
| Example | MD5, bcrypt | AES, RSA |

### 2. Why Never Store Plaintext

**Bad**: `INSERT INTO users VALUES ('john', 'password123');`  
**Good**: `INSERT INTO users VALUES ('john', '5f4dcc3b...');`

Benefits:
- Administrators cannot see passwords
- Database theft doesn't expose passwords
- Verification by comparison, not decryption

### 3. Salt Demonstration

Without salt: `password123 → 482c811da5d... (always same)`  
With unique salt: `password123 + salt1 → a7f3c2e... (different each time)`

**New in this version**: Every password entry now automatically gets a unique salt!

### 4. Password Strength Requirements

This application enforces modern password requirements:
- **Minimum 8 characters** (recommended 12+)
- **At least one uppercase letter** (A-Z)
- **At least one lowercase letter** (a-z)
- **At least one digit** (0-9)
- **At least one special symbol** (!@#$%^&*...)

Weak passwords trigger a warning, allowing users to make informed decisions.

### 5. Timing-Attack Protection

The application uses `hmac.compare_digest()` for password hash comparison, which:
- Takes constant time regardless of where hashes differ
- Prevents timing attacks that could leak information
- Is a security best practice for comparing secrets

## 🧪 Testing

```bash
# Run all 35 tests
python3 -m pytest test_word_manager.py -v

# With coverage
python3 -m pytest test_word_manager.py --cov=.
```

## ⚠️ Limitations (By Design)

1. **Weak Hashing**: MD5/MD4 are fast and insecure
2. **No Key Stretching**: Modern algorithms use iterations
3. **Local Storage**: Database file accessible locally

These limitations are **intentional** to demonstrate why modern algorithms are needed.

## ✨ Recent Improvements

This version includes major enhancements:

### Security
- ✅ **Unique salt per user**: Automatically generated for each entry
- ✅ **Timing-attack protection**: Using `hmac.compare_digest()`
- ✅ **Password strength validation**: Enforces minimum requirements
- ✅ **Weak password warnings**: Alerts users before saving weak passwords

### GUI Enhancements
- ✅ **Enhanced interface**: Better layout, colors, and visual feedback
- ✅ **Edit entries**: Modify service names and usernames
- ✅ **Change passwords**: Update passwords with verification
- ✅ **Action logs**: Monitor all activities (passwords never logged)
- ✅ **Delete functionality**: Remove entries through GUI
- ✅ **Improved password generation**: Dedicated buttons in multiple tabs

### Code Quality
- ✅ **Modular design**: Clean separation between GUI and backend
- ✅ **Comprehensive logging**: Track all actions without exposing secrets
- ✅ **Better error handling**: Clear feedback for all operations

## 🔮 Suggested Future Improvements

1. Replace MD5/MD4 with bcrypt/Argon2 (production-ready)
2. Add master password encryption for database
3. Implement password expiration policies
4. Check passwords against breach databases (Have I Been Pwned API)
5. Add password history to prevent reuse
6. Implement two-factor authentication demonstration

## 📖 References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Python secrets module](https://docs.python.org/3/library/secrets.html)
- [Password Hashing Competition](https://www.password-hashing.net/)

## 📄 License

Educational project. Use for learning only.

**DO NOT use for real password management!**

Use established solutions: 1Password, Bitwarden, KeePass

---

**Remember**: This is an educational tool. Never use MD5/MD4 for real passwords!
