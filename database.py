"""
Database Module
Handles all database operations for storing password manager entries.
Uses SQLite for simplicity and portability.

EDUCATIONAL NOTE: This module demonstrates secure password storage practices:
1. Passwords are NEVER stored in plaintext
2. Only cryptographic hashes of passwords are stored
3. Even database administrators cannot recover original passwords
4. This prevents password leaks if the database is compromised

SECURITY WARNING: This implementation uses MD5/MD4 for educational purposes only.
Production password managers MUST use:
- bcrypt (industry standard for password hashing)
- scrypt (memory-hard, resistant to hardware attacks)
- Argon2 (winner of Password Hashing Competition)

IMPORTANT CONCEPTS:
- Hashing vs Encryption:
  * Hashing is ONE-WAY: password -> hash (cannot reverse)
  * Encryption is TWO-WAY: plaintext <-> ciphertext (can reverse with key)
  * Password storage uses HASHING, not encryption
  * This ensures passwords cannot be decrypted, only verified by comparison
"""

import sqlite3
import os
from datetime import datetime


class DatabaseError(Exception):
    """Custom exception for database-related errors."""
    pass


class Database:
    """
    Database handler for password manager entries.
    
    Schema:
        id: Unique entry identifier (auto-increment)
        service: Name of service/website/account
        username: Username for the account
        password_hash: MD5/MD4 hash of the password (NEVER plaintext)
        algorithm: Hash algorithm used ('md5' or 'md4')
        salt: Optional salt used in hashing (hex string)
        created_at: Timestamp when entry was created
    """
    
    def __init__(self, db_path='passwords.db'):
        """
        Initialize database connection and create table if not exists.
        
        Args:
            db_path: Path to SQLite database file
            
        Raises:
            DatabaseError: If database connection or initialization fails
        """
        self.db_path = db_path
        try:
            self.conn = sqlite3.connect(db_path)
            self.cursor = self.conn.cursor()
            self._create_table()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to initialize database: {e}")
    
    def _create_table(self):
        """
        Create the passwords table if it doesn't exist.
        
        Educational Note:
            - password_hash is NOT NULL to ensure we never store empty passwords
            - service and username together should identify unique accounts
            - salt is optional but recommended for additional security
            - created_at helps track when passwords were created
        """
        try:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    salt TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(service, username)
                )
            ''')
            self.conn.commit()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to create table: {e}")
    
    def add_entry(self, service, username, password_hash, algorithm, salt=None):
        """
        Add a password entry to the database.
        
        SECURITY: This function stores the PASSWORD HASH, not the password itself.
        The plaintext password should NEVER reach this function.
        
        Args:
            service: Service/website/account name (e.g., "Gmail", "GitHub")
            username: Username for the account
            password_hash: Cryptographic hash of the password
            algorithm: Algorithm used ('md5' or 'md4')
            salt: Optional salt used (bytes or string, stored as hex)
            
        Returns:
            int: ID of newly created entry, or None if entry already exists
            
        Raises:
            ValueError: If required parameters are invalid
            DatabaseError: If database operation fails
            
        Educational Note:
            We store the hash, not the password, so even if someone steals the
            database file, they cannot retrieve the original passwords.
        """
        # Input validation
        if not service or not isinstance(service, str):
            raise ValueError("Service must be a non-empty string")
        
        if not username or not isinstance(username, str):
            raise ValueError("Username must be a non-empty string")
        
        if not password_hash or not isinstance(password_hash, str):
            raise ValueError("Password hash must be a non-empty string")
        
        if not algorithm or not isinstance(algorithm, str):
            raise ValueError("Algorithm must be a non-empty string")
        
        try:
            # Convert salt to hex string for storage if provided
            salt_hex = None
            if salt is not None:
                if isinstance(salt, bytes):
                    salt_hex = salt.hex()
                elif isinstance(salt, str):
                    salt_hex = salt
                else:
                    raise ValueError(f"Salt must be bytes or string, got {type(salt).__name__}")
            
            self.cursor.execute(
                '''INSERT INTO passwords (service, username, password_hash, algorithm, salt)
                   VALUES (?, ?, ?, ?, ?)''',
                (service, username, password_hash, algorithm, salt_hex)
            )
            self.conn.commit()
            return self.cursor.lastrowid
        except sqlite3.IntegrityError:
            # Entry already exists (UNIQUE constraint on service + username)
            return None
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to add entry: {e}")
    
    def get_entry(self, service, username):
        """
        Retrieve a specific password entry.
        
        Args:
            service: Service name
            username: Username
            
        Returns:
            tuple: (id, service, username, password_hash, algorithm, salt, created_at)
                   or None if not found
            
        Raises:
            DatabaseError: If database query fails
        """
        if not service or not username:
            raise ValueError("Service and username must be non-empty")
        
        try:
            self.cursor.execute(
                '''SELECT id, service, username, password_hash, algorithm, salt, created_at
                   FROM passwords WHERE service = ? AND username = ?''',
                (service, username)
            )
            return self.cursor.fetchone()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to retrieve entry: {e}")
    
    def get_all_entries(self):
        """
        Retrieve all password entries.
        
        Returns:
            list: List of tuples (id, service, username, password_hash, algorithm, salt, created_at)
            
        Raises:
            DatabaseError: If database query fails
            
        Educational Note:
            Even though we retrieve password_hash here, it should NEVER be
            displayed to the user. Hashes should only be used for verification.
        """
        try:
            self.cursor.execute(
                '''SELECT id, service, username, password_hash, algorithm, salt, created_at
                   FROM passwords ORDER BY service, username'''
            )
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to retrieve entries: {e}")
    
    def delete_entry(self, service, username):
        """
        Delete a password entry.
        
        Args:
            service: Service name
            username: Username
            
        Returns:
            bool: True if deleted, False if not found
            
        Raises:
            DatabaseError: If database operation fails
        """
        if not service or not username:
            raise ValueError("Service and username must be non-empty")
        
        try:
            self.cursor.execute(
                'DELETE FROM passwords WHERE service = ? AND username = ?',
                (service, username)
            )
            self.conn.commit()
            return self.cursor.rowcount > 0
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to delete entry: {e}")
    
    def close(self):
        """
        Close the database connection.
        
        Raises:
            DatabaseError: If closing connection fails
        """
        try:
            if self.conn:
                self.conn.close()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to close database: {e}")
