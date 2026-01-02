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
    salt TEXT,                    -- Optional salt
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
With salt: `password123 + salt1 → a7f3c2e... (different each time)`

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

## 🔮 Suggested Improvements

1. Replace MD5/MD4 with bcrypt
2. Add master password encryption
3. Implement password expiration
4. Check against breach databases
5. Create GUI interface

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
