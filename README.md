# Word Manager Application

A simple CLI application to securely manage words by storing their cryptographic hashes. Words are never stored in plain text - only their MD5 or MD4 hashes are saved in the database.

## ⚠️ Security Notice

**MD5 and MD4 are cryptographically broken hash functions and should NOT be used for security purposes in production environments.** They are vulnerable to collision attacks and are considered obsolete for cryptographic use. This implementation is for **educational purposes only**.

## Features

- **Add Word**: Hash a word and store it in the database
- **List Hashes**: Display all stored hashes with their algorithms
- **Verify Word**: Check if a word exists by hashing and comparing
- **Dual Algorithm Support**: Choose between MD5 (default) or MD4 hashing

## Project Structure

```
projeto-final/
├── word_manager.py    # Main CLI application
├── database.py        # Database operations (SQLite)
├── hash_utils.py      # Hashing utilities
├── requirements.txt   # Dependencies (none required)
├── .gitignore        # Excludes database files
└── README.md         # This file
```

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only standard library)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/blankV0/projeto-final.git
cd projeto-final
```

2. Make the script executable (optional):
```bash
chmod +x word_manager.py
```

## Usage

### Add a Word

Add a word using MD5 (default):
```bash
python3 word_manager.py add myword
```

Add a word using MD4:
```bash
python3 word_manager.py add myword --algo md4
```

### List All Hashes

Display all stored hashes:
```bash
python3 word_manager.py list
```

### Verify a Word

Check if a word exists in the database:
```bash
python3 word_manager.py verify myword
```

Verify using specific algorithm:
```bash
python3 word_manager.py verify myword --algo md4
```

### Help

Display help information:
```bash
python3 word_manager.py --help
python3 word_manager.py add --help
```

## Example Session

```bash
# Add some words
$ python3 word_manager.py add password
Word added successfully!
Hash (md5): 5f4dcc3b5aa765d61d8327deb882cf99

$ python3 word_manager.py add secret --algo md4
Word added successfully!
Hash (md4): 7c6fef5b54558c7d1c3ad0f8b2b0b8f7

# List all hashes
$ python3 word_manager.py list

Stored hashes (2 total):
--------------------------------------------------
ID: 2 | Algorithm: md4 | Hash: 7c6fef5b54558c7d1c3ad0f8b2b0b8f7
ID: 1 | Algorithm: md5 | Hash: 5f4dcc3b5aa765d61d8327deb882cf99

# Verify a word
$ python3 word_manager.py verify password
✓ Word exists in database!
Hash (md5): 5f4dcc3b5aa765d61d8327deb882cf99

$ python3 word_manager.py verify unknown
✗ Word NOT found in database.
Hash (md5): 5e543256c480ac577d30f76f9120eb74
```

## How It Works

1. **Hashing**: When you add a word, it's immediately hashed using the selected algorithm (MD5 or MD4)
2. **Storage**: Only the hash is stored in the SQLite database - the original word is never saved
3. **Verification**: To verify a word, the application hashes your input and compares it against stored hashes
4. **Database**: Uses SQLite (`words.db`) to persistently store hashes with timestamps

## Technical Details

- **Database**: SQLite3 with a simple schema (id, hash, algorithm, created_at)
- **Hashing**: Uses Python's `hashlib` module for MD5 and MD4
- **CLI**: Built with `argparse` for clean command-line interface
- **No Dependencies**: Uses only Python standard library modules

## License

This is an educational project. Use at your own risk.
