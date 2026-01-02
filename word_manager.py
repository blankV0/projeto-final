#!/usr/bin/env python3
"""
Word Manager Application
A simple CLI application to manage words securely by storing their hashes.

SECURITY NOTE: MD5 and MD4 are cryptographically broken hash functions and 
should NOT be used for security purposes in production. This implementation 
is for educational purposes only.
"""

import sys
import argparse
from database import Database
from hash_utils import hash_word


def add_word(db, word, algorithm='md5'):
    """
    Add a word to the database by hashing it first.
    
    Args:
        db: Database instance
        word: The word to add
        algorithm: Hashing algorithm to use ('md5' or 'md4')
    """
    hashed = hash_word(word, algorithm)
    if db.add_hash(hashed, algorithm):
        print(f"Word added successfully!")
        print(f"Hash ({algorithm}): {hashed}")
    else:
        print(f"Hash already exists in database.")


def list_hashes(db):
    """
    List all stored hashes in the database.
    
    Args:
        db: Database instance
    """
    hashes = db.get_all_hashes()
    if not hashes:
        print("No hashes stored in database.")
        return
    
    print(f"\nStored hashes ({len(hashes)} total):")
    print("-" * 50)
    for hash_id, hash_value, algorithm in hashes:
        print(f"ID: {hash_id} | Algorithm: {algorithm} | Hash: {hash_value}")


def verify_word(db, word, algorithm='md5'):
    """
    Verify if a word exists in the database by hashing it and comparing.
    
    Args:
        db: Database instance
        word: The word to verify
        algorithm: Hashing algorithm to use ('md5' or 'md4')
    """
    hashed = hash_word(word, algorithm)
    if db.hash_exists(hashed):
        print(f"✓ Word exists in database!")
        print(f"Hash ({algorithm}): {hashed}")
    else:
        print(f"✗ Word NOT found in database.")
        print(f"Hash ({algorithm}): {hashed}")


def main():
    """Main entry point for the Word Manager application."""
    parser = argparse.ArgumentParser(
        description='Word Manager - Securely store and verify words using hashing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s add myword              # Add a word using MD5 (default)
  %(prog)s add myword --algo md4   # Add a word using MD4
  %(prog)s list                     # List all stored hashes
  %(prog)s verify myword            # Check if a word exists
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add a new word')
    add_parser.add_argument('word', help='Word to add')
    add_parser.add_argument('--algo', choices=['md5', 'md4'], default='md5',
                           help='Hashing algorithm to use (default: md5)')
    
    # List command
    subparsers.add_parser('list', help='List all stored hashes')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify if a word exists')
    verify_parser.add_argument('word', help='Word to verify')
    verify_parser.add_argument('--algo', choices=['md5', 'md4'], default='md5',
                              help='Hashing algorithm to use (default: md5)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize database
    db = Database()
    
    # Execute command
    if args.command == 'add':
        add_word(db, args.word, args.algo)
    elif args.command == 'list':
        list_hashes(db)
    elif args.command == 'verify':
        verify_word(db, args.word, args.algo)
    
    # Close database connection
    db.close()


if __name__ == '__main__':
    main()
