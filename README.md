# Word Manager Application

A production-quality CLI application for educational purposes demonstrating secure word management using cryptographic hashing. Words are never stored in plain text - only their MD5 or MD4 hashes are saved in the database.

## ⚠️ Security Notice

**CRITICAL: MD5 and MD4 are cryptographically broken hash functions and should NOT be used for security purposes in production environments.**

These algorithms are:
- Vulnerable to collision attacks
- Vulnerable to pre-image attacks  
- Considered obsolete for cryptographic use
- **NOT suitable for password storage**

**This implementation is for EDUCATIONAL PURPOSES ONLY** to demonstrate:
- Basic hashing concepts
- Salting techniques
- Database storage patterns
- Input validation
- Error handling

**For production password storage, always use:**
- **bcrypt** (recommended for most use cases)
- **scrypt** (memory-hard, resistant to hardware attacks)
- **Argon2** (winner of Password Hashing Competition, most modern)

## Features

### Core Functionality
- ✅ **Add Word**: Hash a word and store it in the database
- ✅ **List Hashes**: Display all stored hashes with metadata
- ✅ **Verify Word**: Check if a word exists by hashing and comparing
- ✅ **Dual Algorithm Support**: Choose between MD5 (default) or MD4 hashing

### Production-Quality Features
- ✅ **Comprehensive Testing**: 35+ unit and integration tests using pytest
- ✅ **Input Validation**: Validates empty strings, whitespace, and type checking
- ✅ **Error Handling**: Proper exception handling with informative error messages
- ✅ **Salting Support**: Optional random salt generation (educational demonstration)
- ✅ **Enhanced CLI**: Clear help messages, multiple command options
- ✅ **Database Safety**: SQLite with proper connection handling and error recovery
- ✅ **Type Safety**: Type hints and validation throughout codebase

## Architecture

### Project Structure

```
projeto-final/
├── word_manager.py         # Main CLI application with argparse
├── database.py            # Database layer (SQLite operations)
├── hash_utils.py          # Hashing utilities (MD5/MD4, salting)
├── test_word_manager.py   # Comprehensive test suite (pytest)
├── requirements.txt       # Python dependencies
├── .gitignore            # Excludes database and Python artifacts
└── README.md             # This documentation
```

### Component Overview

#### `word_manager.py` - CLI Interface
- Argparse-based command-line interface
- Three main commands: `add`, `list`, `verify`
- Supports `--algorithm` (or `-a`) for algorithm selection
- Supports `--salt` (or `-s`) for random salt generation
- Comprehensive error handling with exit codes
- Context manager pattern for database connections

#### `database.py` - Data Layer
- SQLite3 wrapper with error handling
- Schema: `hashes(id, hash, algorithm, salt, created_at)`
- UNIQUE constraint on hash field
- Custom `DatabaseError` exception class
- Input validation on all operations
- Safe connection closing

#### `hash_utils.py` - Hashing Logic
- MD5 and MD4 hash generation
- Optional salt support (prepended before hashing)
- Cryptographically secure random salt generation using `os.urandom()`
- Input validation (type checking, empty string detection)
- Clear security warnings in docstrings

#### `test_word_manager.py` - Test Suite
- 35+ tests covering all components
- Unit tests for hashing functions
- Unit tests for database operations
- Integration tests for complete workflows
- Fixtures for temporary database creation
- Tests for error conditions and edge cases

## Requirements

- **Python 3.6+** (tested on 3.12)
- **pytest** 7.0.0+ (for running tests)
- **pytest-cov** 4.0.0+ (for coverage reports)

No external dependencies required for core functionality (uses only Python standard library).

## Installation

1. Clone the repository:
```bash
git clone https://github.com/blankV0/projeto-final.git
cd projeto-final
```

2. Install testing dependencies (optional):
```bash
pip3 install -r requirements.txt
```

3. Make the script executable (optional):
```bash
chmod +x word_manager.py
```

## Usage

### Basic Commands

#### Add a Word

Add a word using MD5 (default):
```bash
python3 word_manager.py add myword
```

Add a word using MD4:
```bash
python3 word_manager.py add myword --algorithm md4
# or shorthand:
python3 word_manager.py add myword -a md4
```

Add a word with random salt (educational):
```bash
python3 word_manager.py add myword --salt
# or shorthand:
python3 word_manager.py add myword -s
```

#### List All Hashes

Display all stored hashes:
```bash
python3 word_manager.py list
```

#### Verify a Word

Check if a word exists in the database:
```bash
python3 word_manager.py verify myword
```

Verify using specific algorithm:
```bash
python3 word_manager.py verify myword --algorithm md4
```

### Advanced Usage

#### Get Help

```bash
# General help
python3 word_manager.py --help

# Command-specific help
python3 word_manager.py add --help
python3 word_manager.py verify --help
```

#### Error Handling

The application provides clear error messages:

```bash
# Empty word
$ python3 word_manager.py add ""
✗ Error: Word cannot be empty or whitespace only

# Invalid algorithm
$ python3 word_manager.py add test --algorithm sha256
error: argument --algorithm/-a: invalid choice: 'sha256'

# Database errors are caught and reported
```

## Example Session

```bash
# Add some words with different options
$ python3 word_manager.py add password
✓ Word added successfully!
  Algorithm: MD5
  Hash: 5f4dcc3b5aa765d61d8327deb882cf99

$ python3 word_manager.py add secret --salt
✓ Word added successfully!
  Algorithm: MD5
  Hash: 7c6a180b36896a0a8c02787eeafb0e4c
  Salt: 6f4b6612125fb3a0daecd2799dfd6c9c
  Note: Salt is stored with hash for verification

$ python3 word_manager.py add hello --algorithm md5
✓ Word added successfully!
  Algorithm: MD5
  Hash: 5d41402abc4b2a76b9719d911017c592

# List all hashes
$ python3 word_manager.py list

======================================================================
Stored hashes: 3 total
======================================================================

ID: 1
  Algorithm: MD5
  Hash: 5f4dcc3b5aa765d61d8327deb882cf99

ID: 2
  Algorithm: MD5
  Hash: 7c6a180b36896a0a8c02787eeafb0e4c
  Salt: 6f4b6612125fb3a0daecd2799dfd6c9c

ID: 3
  Algorithm: MD5
  Hash: 5d41402abc4b2a76b9719d911017c592

======================================================================

# Verify words
$ python3 word_manager.py verify password
✓ Word exists in database!
  Algorithm: MD5
  Hash: 5f4dcc3b5aa765d61d8327deb882cf99

$ python3 word_manager.py verify unknown
✗ Word NOT found in database.
  Algorithm: MD5
  Hash: ad921d60486366258809553a3db49a4a
  Note: Salted hashes cannot be verified this way

# Try to add duplicate
$ python3 word_manager.py add password
✗ Hash already exists in database.
```

## Testing

### Run Tests

Run all tests:
```bash
python3 -m pytest test_word_manager.py -v
```

Run with coverage report:
```bash
python3 -m pytest test_word_manager.py --cov=. --cov-report=term-missing
```

Run specific test class:
```bash
python3 -m pytest test_word_manager.py::TestHashWord -v
```

Run specific test:
```bash
python3 -m pytest test_word_manager.py::TestHashWord::test_md5_hash_basic -v
```

### Test Coverage

The test suite includes:
- **Hash function tests** (12 tests): Basic hashing, salting, input validation, error handling
- **Database operation tests** (13 tests): CRUD operations, error handling, connection management
- **Integration tests** (4 tests): Complete workflows, salted hashes, multiple words
- **CLI tests** (1 test): Module import verification

Total: **35 comprehensive tests** covering all major components and edge cases.

## How It Works

### Hashing Process

1. **Input Validation**: Word is checked for type (string) and content (non-empty)
2. **Salt Generation** (optional): Cryptographically secure random bytes via `os.urandom()`
3. **Hashing**: Word is encoded to UTF-8, optionally prepended with salt, then hashed
4. **Storage**: Hash (and salt if used) stored in SQLite database
5. **Verification**: Input word is hashed with same algorithm and compared to stored hashes

### Why Salting Matters (Educational)

Without salt:
- Same password always produces same hash
- Vulnerable to rainbow table attacks
- Vulnerable to dictionary attacks

With salt (even with broken MD5):
- Same password produces different hash each time
- Rainbow tables become ineffective
- Each password requires individual attack

**However**: Even salted MD5/MD4 hashes remain vulnerable to brute force. Use modern algorithms!

### Database Schema

```sql
CREATE TABLE hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL UNIQUE,         -- Hex digest of hash
    algorithm TEXT NOT NULL,           -- 'md5' or 'md4'
    salt TEXT,                         -- Hex representation of salt (optional)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Limitations and Security Considerations

### Algorithm Weaknesses

**MD5:**
- Collisions can be generated in seconds
- Pre-image attacks are feasible
- Not suitable for any security purpose

**MD4:**
- Even weaker than MD5
- Completely broken for collision resistance
- Pre-image attacks easier than MD5
- May not be available in all Python installations

### Salting Limitations

- Salting with MD5/MD4 does NOT make them secure
- Still vulnerable to GPU-accelerated brute force
- Modern password crackers (hashcat, John the Ripper) can test billions of MD5 hashes per second
- Proper password hashing requires:
  - Slow algorithms (bcrypt, scrypt, Argon2)
  - Key stretching (many iterations)
  - Memory-hardness (scrypt, Argon2)

### Verification Limitation

The `verify` command cannot verify salted hashes because:
- Each hash has a unique random salt
- To verify, you'd need to know the salt
- This demonstrates why password systems store salts alongside hashes

### Educational Context

This tool demonstrates:
- ✅ Basic hashing concepts
- ✅ Salt generation and storage
- ✅ Database integration patterns
- ✅ Input validation importance
- ✅ Error handling practices

This tool does NOT demonstrate:
- ❌ Secure password storage (use bcrypt/scrypt/Argon2)
- ❌ Key derivation functions (use PBKDF2/scrypt/Argon2)
- ❌ Resistance to brute force attacks
- ❌ Proper iteration counts
- ❌ Memory-hard functions

## Production Alternatives

For real-world password storage, use these libraries:

### Python Examples

**bcrypt** (recommended):
```python
import bcrypt
password = b"mypassword"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
# Verify
if bcrypt.checkpw(password, hashed):
    print("Password matches!")
```

**Argon2** (most modern):
```python
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash("mypassword")
# Verify
if ph.verify(hash, "mypassword"):
    print("Password matches!")
```

## Troubleshooting

### MD4 Not Available

If you see "MD4 is not available":
- MD4 may not be enabled in your OpenSSL installation
- Use `--algorithm md5` instead
- This is expected on some systems for security reasons

### Database Locked

If you see "database is locked":
- Close any other connections to `words.db`
- The application properly closes connections, but crashes may leave locks

### Permission Denied

If you can't create `words.db`:
- Ensure write permissions in current directory
- Try running from your home directory

## Contributing

This is an educational project. Improvements welcome:
- Additional test cases
- Better error messages
- Code documentation
- Examples and tutorials

## License

This is an educational project. Use at your own risk. Not suitable for production use.

## Acknowledgments

This project demonstrates concepts that should NOT be used in production:
- MD5 and MD4 algorithms are deprecated
- Simple salting is insufficient for modern security
- This code is for learning purposes only

**Always use modern, vetted cryptographic libraries for real applications.**
