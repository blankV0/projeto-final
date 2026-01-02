"""
Database Module
Handles all database operations for storing and retrieving hashed words.
Uses SQLite for simplicity and portability.
"""

import sqlite3
import os


class DatabaseError(Exception):
    """Custom exception for database-related errors."""
    pass


class Database:
    """Database handler for word hashes with salt support."""
    
    def __init__(self, db_path='words.db'):
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
        Create the hashes table if it doesn't exist.
        Updated schema includes optional salt column.
        """
        try:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash TEXT NOT NULL UNIQUE,
                    algorithm TEXT NOT NULL,
                    salt TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            self.conn.commit()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to create table: {e}")
    
    def add_hash(self, hash_value, algorithm, salt=None):
        """
        Add a hash to the database with optional salt.
        
        Args:
            hash_value: The hash string to store
            algorithm: The algorithm used to generate the hash
            salt: Optional salt used (bytes or string, stored as hex string)
            
        Returns:
            bool: True if added successfully, False if already exists
            
        Raises:
            DatabaseError: If database operation fails unexpectedly
        """
        if not hash_value or not isinstance(hash_value, str):
            raise ValueError("Hash value must be a non-empty string")
        
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
                'INSERT INTO hashes (hash, algorithm, salt) VALUES (?, ?, ?)',
                (hash_value, algorithm, salt_hex)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Hash already exists (UNIQUE constraint violation)
            return False
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to add hash: {e}")
    
    def hash_exists(self, hash_value):
        """
        Check if a hash exists in the database.
        
        Args:
            hash_value: The hash string to check
            
        Returns:
            bool: True if hash exists, False otherwise
            
        Raises:
            DatabaseError: If database query fails
        """
        if not hash_value or not isinstance(hash_value, str):
            raise ValueError("Hash value must be a non-empty string")
        
        try:
            self.cursor.execute(
                'SELECT COUNT(*) FROM hashes WHERE hash = ?',
                (hash_value,)
            )
            count = self.cursor.fetchone()[0]
            return count > 0
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to check hash existence: {e}")
    
    def get_all_hashes(self):
        """
        Retrieve all hashes from the database.
        
        Returns:
            list: List of tuples (id, hash, algorithm, salt)
            
        Raises:
            DatabaseError: If database query fails
        """
        try:
            self.cursor.execute(
                'SELECT id, hash, algorithm, salt FROM hashes ORDER BY created_at DESC'
            )
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to retrieve hashes: {e}")
    
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
