#!/usr/bin/env python3
"""
Word Manager Application
A production-quality CLI application to manage words securely by storing their hashes.

SECURITY NOTE: MD5 and MD4 are cryptographically broken hash functions and 
should NOT be used for security purposes in production. This implementation 
is for educational purposes only to demonstrate hashing concepts.

For production password storage, use bcrypt, scrypt, or Argon2.
"""

import argparse
import sys
from database import Database, DatabaseError
from hash_utils import hash_word, generate_salt


def add_word(db, word, algorithm='md5', use_salt=False):
    """
    Add a word to the database by hashing it first.
    
    Args:
        db: Database instance
        word: The word to add
        algorithm: Hashing algorithm to use ('md5' or 'md4')
        use_salt: Whether to use a random salt (educational purposes)
        
    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    try:
        # Generate salt if requested
        salt = generate_salt() if use_salt else None
        
        # Hash the word
        hashed = hash_word(word, algorithm, salt)
        
        # Store in database
        if db.add_hash(hashed, algorithm, salt):
            print(f"✓ Word added successfully!")
            print(f"  Algorithm: {algorithm.upper()}")
            print(f"  Hash: {hashed}")
            if salt:
                print(f"  Salt: {salt.hex()}")
                print(f"  Note: Salt is stored with hash for verification")
            return 0
        else:
            print(f"✗ Hash already exists in database.")
            return 1
    except ValueError as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 1
    except TypeError as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 1
    except DatabaseError as e:
        print(f"✗ Database error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        return 1


def list_hashes(db):
    """
    List all stored hashes in the database.
    
    Args:
        db: Database instance
        
    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    try:
        hashes = db.get_all_hashes()
        if not hashes:
            print("No hashes stored in database.")
            return 0
        
        print(f"\n{'='*70}")
        print(f"Stored hashes: {len(hashes)} total")
        print(f"{'='*70}")
        
        for hash_id, hash_value, algorithm, salt in hashes:
            print(f"\nID: {hash_id}")
            print(f"  Algorithm: {algorithm.upper()}")
            print(f"  Hash: {hash_value}")
            if salt:
                print(f"  Salt: {salt}")
        
        print(f"\n{'='*70}\n")
        return 0
    except DatabaseError as e:
        print(f"✗ Database error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        return 1


def verify_word(db, word, algorithm='md5'):
    """
    Verify if a word exists in the database by hashing it and comparing.
    
    Note: For salted hashes, this will not work as expected since each word
    has a unique salt. This demonstrates why salted hashes require storing
    the salt alongside the hash.
    
    Args:
        db: Database instance
        word: The word to verify
        algorithm: Hashing algorithm to use ('md5' or 'md4')
        
    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    try:
        # Hash without salt (for unsalted hashes)
        hashed = hash_word(word, algorithm, salt=None)
        
        if db.hash_exists(hashed):
            print(f"✓ Word exists in database!")
            print(f"  Algorithm: {algorithm.upper()}")
            print(f"  Hash: {hashed}")
            return 0
        else:
            print(f"✗ Word NOT found in database.")
            print(f"  Algorithm: {algorithm.upper()}")
            print(f"  Hash: {hashed}")
            print(f"  Note: Salted hashes cannot be verified this way")
            return 1
    except ValueError as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 1
    except TypeError as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 1
    except DatabaseError as e:
        print(f"✗ Database error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        return 1


def main():
    """Main entry point for the Word Manager application."""
    parser = argparse.ArgumentParser(
        prog='word_manager.py',
        description='''Word Manager - Educational tool for storing and verifying word hashes.

⚠️  SECURITY WARNING: MD5 and MD4 are cryptographically broken.
    This tool is for EDUCATIONAL PURPOSES ONLY.
    Never use MD5/MD4 for real password storage!
    Use bcrypt, scrypt, or Argon2 in production.''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Add a word with MD5 (default)
  %(prog)s add myword
  
  # Add a word with MD4
  %(prog)s add myword --algorithm md4
  
  # Add a word with random salt (educational)
  %(prog)s add myword --salt
  
  # List all stored hashes
  %(prog)s list
  
  # Verify if a word exists
  %(prog)s verify myword
  
  # Get help for a specific command
  %(prog)s add --help

For more information, see README.md
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add command
    add_parser = subparsers.add_parser(
        'add',
        help='Add a new word by hashing and storing it',
        description='Hash a word and store it in the database'
    )
    add_parser.add_argument(
        'word',
        help='Word to add (non-empty string)'
    )
    add_parser.add_argument(
        '--algorithm', '-a',
        choices=['md5', 'md4'],
        default='md5',
        help='Hashing algorithm: md5 (default) or md4'
    )
    add_parser.add_argument(
        '--salt', '-s',
        action='store_true',
        help='Use random salt (educational - demonstrates salting concept)'
    )
    
    # List command
    list_parser = subparsers.add_parser(
        'list',
        help='List all stored hashes',
        description='Display all hashes stored in the database'
    )
    
    # Verify command
    verify_parser = subparsers.add_parser(
        'verify',
        help='Verify if a word exists',
        description='Hash a word and check if it exists in the database'
    )
    verify_parser.add_argument(
        'word',
        help='Word to verify (non-empty string)'
    )
    verify_parser.add_argument(
        '--algorithm', '-a',
        choices=['md5', 'md4'],
        default='md5',
        help='Hashing algorithm: md5 (default) or md4'
    )
    
    args = parser.parse_args()
    
    # Show help if no command specified
    if not args.command:
        parser.print_help()
        return 0
    
    # Initialize database with error handling
    try:
        db = Database()
    except DatabaseError as e:
        print(f"✗ Failed to initialize database: {e}", file=sys.stderr)
        return 1
    
    # Execute command
    exit_code = 0
    try:
        if args.command == 'add':
            exit_code = add_word(db, args.word, args.algorithm, args.salt)
        elif args.command == 'list':
            exit_code = list_hashes(db)
        elif args.command == 'verify':
            exit_code = verify_word(db, args.word, args.algorithm)
    finally:
        # Always close database connection
        try:
            db.close()
        except Exception:
            pass  # Ignore errors on close
    
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
