#!/usr/bin/env python3
"""
Educational Password Manager Application
A CLI application demonstrating secure password management practices.

SECURITY NOTE: MD5 and MD4 are cryptographically broken hash functions and 
should NOT be used for security purposes in production. This implementation 
is for EDUCATIONAL PURPOSES ONLY to demonstrate password management concepts.

IMPORTANT LEARNING OBJECTIVES:
1. Passwords must NEVER be stored in plaintext
2. Only cryptographic hashes of passwords should be stored
3. Hashing is one-way (cannot be reversed to get password)
4. Salting prevents rainbow table attacks
5. Strong passwords use multiple character types and sufficient length

For production password managers, use established solutions like:
- 1Password, LastPass, Bitwarden (cloud-based)
- KeePass, KeePassXC (local storage)
Or use libraries like: bcrypt, scrypt, or Argon2 for password hashing.
"""

import argparse
import sys
import getpass
from database import Database, DatabaseError
from hash_utils import hash_password, generate_salt
from password_generator import generate_password, estimate_password_strength, generate_passphrase


def add_entry(db, service, username, password=None, algorithm='md5', use_salt=False, 
              generate=False, pass_length=16):
    """
    Add a new password entry to the database.
    
    EDUCATIONAL NOTE: This function demonstrates the complete password storage flow:
    1. Get or generate password (plaintext - only exists in memory temporarily)
    2. Hash the password (one-way cryptographic function)
    3. Store ONLY the hash (never the plaintext password)
    4. Original password is discarded from memory
    
    Args:
        db: Database instance
        service: Service/website name
        username: Username for the account
        password: Password to hash and store (if None, must generate=True)
        algorithm: Hashing algorithm ('md5' or 'md4')
        use_salt: Whether to use random salt
        generate: Whether to generate a random password
        pass_length: Length for generated password
        
    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    try:
        # Generate password if requested
        if generate:
            password = generate_password(length=pass_length)
            print(f"\n🔐 Generated password: {password}")
            print(f"   ⚠️  WARNING: Save this password immediately!")
            print(f"   This password is displayed only once and won't be shown again.")
            print(f"   Note: Terminal history may log this output.\n")
            
            # Show password strength
            strength, desc = estimate_password_strength(password)
            print(f"   Password strength: {desc}")
            print()
        elif not password:
            print(f"✗ Error: Password is required (use --generate to create one)", file=sys.stderr)
            return 1
        
        # Generate salt if requested
        salt = generate_salt() if use_salt else None
        
        # Hash the password (NEVER store plaintext!)
        password_hash = hash_password(password, algorithm, salt)
        
        # Store in database (only the hash, not the password)
        entry_id = db.add_entry(service, username, password_hash, algorithm, salt)
        
        if entry_id:
            print(f"✓ Password entry added successfully!")
            print(f"  Service: {service}")
            print(f"  Username: {username}")
            print(f"  Algorithm: {algorithm.upper()}")
            if salt:
                print(f"  Salt: {salt.hex()[:32]}... (salted for extra security)")
            print(f"\n  Educational Note: The password is hashed and stored securely.")
            print(f"  Even database administrators cannot see your password!")
            return 0
        else:
            print(f"✗ Entry already exists for {service}/{username}.")
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


def list_entries(db, show_details=False):
    """
    List all password entries.
    
    EDUCATIONAL NOTE: This function demonstrates proper password manager behavior:
    - Display service names and usernames (metadata is safe to show)
    - NEVER display passwords or password hashes
    - Hashes should only be used internally for verification
    
    Args:
        db: Database instance
        show_details: Whether to show additional details (NOT passwords!)
        
    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    try:
        entries = db.get_all_entries()
        
        if not entries:
            print("No password entries stored.")
            print("\nUse 'password_manager.py add' to create your first entry.")
            return 0
        
        print(f"\n{'='*70}")
        print(f"Password Manager - Stored Entries ({len(entries)} total)")
        print(f"{'='*70}\n")
        
        for entry_id, service, username, _, algorithm, salt, created_at in entries:
            print(f"🔐 Service: {service}")
            print(f"   Username: {username}")
            
            if show_details:
                print(f"   Algorithm: {algorithm.upper()}")
                if salt:
                    print(f"   Salted: Yes")
                print(f"   Created: {created_at}")
            
            print()
        
        print(f"{'='*70}")
        print(f"\nEducational Note: Passwords are never displayed.")
        print(f"Use 'verify' command to check if a password is correct.\n")
        return 0
        
    except DatabaseError as e:
        print(f"✗ Database error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        return 1


def verify_password(db, service, username, password, algorithm='md5'):
    """
    Verify if a password matches the stored hash.
    
    EDUCATIONAL NOTE: This demonstrates password verification:
    1. Retrieve stored hash from database
    2. Hash the provided password with same algorithm and salt
    3. Compare hashes (if they match, password is correct)
    4. This works because hashing is deterministic (same input = same output)
    
    Args:
        db: Database instance
        service: Service name
        username: Username
        password: Password to verify
        algorithm: Hashing algorithm to use
        
    Returns:
        int: Exit code (0 for success/match, 1 for error/mismatch)
    """
    try:
        # Retrieve entry from database
        entry = db.get_entry(service, username)
        
        if not entry:
            print(f"✗ No entry found for {service}/{username}")
            return 1
        
        entry_id, service, username, stored_hash, stored_algo, salt_hex, created_at = entry
        
        # Convert salt from hex string back to bytes
        salt = bytes.fromhex(salt_hex) if salt_hex else None
        
        # Hash the provided password with the same algorithm and salt
        password_hash = hash_password(password, stored_algo, salt)
        
        # Compare hashes
        if password_hash == stored_hash:
            print(f"✓ Password verified successfully!")
            print(f"  Service: {service}")
            print(f"  Username: {username}")
            print(f"\n  The provided password matches the stored hash.")
            return 0
        else:
            print(f"✗ Password verification failed!")
            print(f"  Service: {service}")
            print(f"  Username: {username}")
            print(f"\n  The provided password does not match.")
            return 1
            
    except ValueError as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 1
    except DatabaseError as e:
        print(f"✗ Database error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        return 1


def generate_password_cmd(length=16, no_symbols=False):
    """
    Generate a strong random password and display it.
    
    EDUCATIONAL NOTE: This demonstrates password generation best practices:
    - Use cryptographically secure random generation (secrets module)
    - Include multiple character types (uppercase, lowercase, digits, symbols)
    - Adequate length (12+ characters minimum, 16+ recommended)
    - Avoid patterns, dictionary words, personal information
    
    Args:
        length: Password length
        no_symbols: If True, exclude special characters
        
    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    try:
        password = generate_password(
            length=length,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_symbols=not no_symbols
        )
        
        print(f"\n🔐 Generated Password:")
        print(f"   {password}")
        print(f"\n   Length: {len(password)} characters")
        
        # Show character composition
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        
        types = []
        if has_upper: types.append("Uppercase")
        if has_lower: types.append("Lowercase")
        if has_digit: types.append("Digits")
        if has_symbol: types.append("Symbols")
        print(f"   Types: {', '.join(types)}")
        
        # Show strength assessment
        strength, desc = estimate_password_strength(password)
        print(f"   Strength: {desc}")
        
        print(f"\n   Educational Note:")
        print(f"   This password was generated using cryptographically secure random")
        print(f"   generation. It's strong because it:")
        print(f"   - Has sufficient length ({length} chars)")
        print(f"   - Uses multiple character types ({len(types)} types)")
        print(f"   - Is truly random (no patterns or dictionary words)")
        print()
        
        return 0
        
    except ValueError as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        return 1


def delete_entry_cmd(db, service, username):
    """
    Delete a password entry.
    
    Args:
        db: Database instance
        service: Service name
        username: Username
        
    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    try:
        if db.delete_entry(service, username):
            print(f"✓ Entry deleted successfully!")
            print(f"  Service: {service}")
            print(f"  Username: {username}")
            return 0
        else:
            print(f"✗ No entry found for {service}/{username}")
            return 1
            
    except DatabaseError as e:
        print(f"✗ Database error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        return 1


def main():
    """Main entry point for the Password Manager application."""
    parser = argparse.ArgumentParser(
        prog='password_manager.py',
        description='''Educational Password Manager - Learn secure password storage practices

⚠️  SECURITY WARNING: MD5 and MD4 are cryptographically broken.
    This tool is for EDUCATIONAL PURPOSES ONLY.
    Never use MD5/MD4 for real password storage!
    Use bcrypt, scrypt, or Argon2 in production.
    
LEARNING OBJECTIVES:
• Understand why passwords must never be stored in plaintext
• Learn the difference between hashing and encryption
• Discover how salting prevents rainbow table attacks
• Practice generating strong, random passwords''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate a strong password
  %(prog)s generate
  
  # Add entry with generated password
  %(prog)s add Gmail john@example.com --generate
  
  # Add entry with manual password
  %(prog)s add GitHub johndoe --password myP@ssw0rd
  
  # Add entry with salt (more secure)
  %(prog)s add Facebook jane@email.com --generate --salt
  
  # List all entries
  %(prog)s list
  
  # Verify a password
  %(prog)s verify Gmail john@example.com
  
  # Delete an entry
  %(prog)s delete Gmail john@example.com

For more information, see README.md
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add command
    add_parser = subparsers.add_parser(
        'add',
        help='Add a new password entry',
        description='Create a new password entry for a service/account'
    )
    add_parser.add_argument('service', help='Service or website name (e.g., Gmail, GitHub)')
    add_parser.add_argument('username', help='Username or email for this service')
    add_parser.add_argument('--password', '-p', help='Password to store (will be hashed)')
    add_parser.add_argument(
        '--generate', '-g',
        action='store_true',
        help='Generate a strong random password'
    )
    add_parser.add_argument(
        '--length', '-l',
        type=int,
        default=16,
        help='Length of generated password (default: 16)'
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
        help='Use random salt (recommended for educational demonstration)'
    )
    
    # List command
    list_parser = subparsers.add_parser(
        'list',
        help='List all password entries',
        description='Display all stored password entries (without showing passwords)'
    )
    list_parser.add_argument(
        '--details', '-d',
        action='store_true',
        help='Show additional details (algorithm, date)'
    )
    
    # Verify command
    verify_parser = subparsers.add_parser(
        'verify',
        help='Verify a password',
        description='Check if a password matches the stored hash'
    )
    verify_parser.add_argument('service', help='Service name')
    verify_parser.add_argument('username', help='Username')
    verify_parser.add_argument(
        '--password', '-p',
        help='Password to verify (will prompt if not provided)'
    )
    
    # Generate command
    generate_parser = subparsers.add_parser(
        'generate',
        help='Generate a strong password',
        description='Generate a cryptographically secure random password'
    )
    generate_parser.add_argument(
        '--length', '-l',
        type=int,
        default=16,
        help='Password length (default: 16, minimum: 8)'
    )
    generate_parser.add_argument(
        '--no-symbols',
        action='store_true',
        help='Exclude special characters'
    )
    
    # Delete command
    delete_parser = subparsers.add_parser(
        'delete',
        help='Delete a password entry',
        description='Remove a password entry from the database'
    )
    delete_parser.add_argument('service', help='Service name')
    delete_parser.add_argument('username', help='Username')
    
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
            exit_code = add_entry(
                db, args.service, args.username, args.password,
                args.algorithm, args.salt, args.generate, args.length
            )
        elif args.command == 'list':
            exit_code = list_entries(db, args.details)
        elif args.command == 'verify':
            password = args.password
            if not password:
                # Prompt for password if not provided (more secure than command line)
                password = getpass.getpass("Enter password to verify: ")
            exit_code = verify_password(db, args.service, args.username, password)
        elif args.command == 'generate':
            exit_code = generate_password_cmd(args.length, args.no_symbols)
        elif args.command == 'delete':
            exit_code = delete_entry_cmd(db, args.service, args.username)
    finally:
        # Always close database connection
        try:
            db.close()
        except Exception:
            pass  # Ignore errors on close
    
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
