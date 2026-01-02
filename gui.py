#!/usr/bin/env python3
"""
Educational Password Manager - Graphical User Interface (GUI)
A Tkinter-based GUI demonstrating secure password management practices.

SECURITY NOTE: MD5 and MD4 are cryptographically broken hash functions and 
should NOT be used for security purposes in production. This implementation 
is for EDUCATIONAL PURPOSES ONLY to demonstrate password management concepts.

This GUI reuses existing modules:
- database.py: Database operations for storing password entries
- hash_utils.py: Password hashing functions (MD5/MD4)
- password_generator.py: Secure password generation

IMPORTANT: This GUI NEVER displays or stores plaintext passwords.
Passwords are hashed immediately before storage and only hashes are stored.
"""

import tkinter as tk
from tkinter import ttk, messagebox

# Import existing modules (NO business logic duplication)
from database import Database, DatabaseError
from hash_utils import hash_password, generate_salt
from password_generator import generate_password, estimate_password_strength


class PasswordManagerGUI:
    """
    Main GUI application for the Educational Password Manager.
    
    This class provides a user-friendly interface that demonstrates
    secure password management concepts without compromising the
    existing CLI architecture.
    
    Key Features:
    - Add new password entries (service, username, password)
    - Generate secure random passwords
    - List stored entries (without showing passwords)
    - Verify passwords against stored hashes
    - Select hashing algorithm (MD5/MD4)
    
    Educational Note:
        This GUI demonstrates the separation between presentation (GUI)
        and business logic (existing modules). All hashing, storage,
        and password generation is handled by the imported modules.
    """
    
    def __init__(self, root):
        """
        Initialize the Password Manager GUI.
        
        Args:
            root: Tkinter root window
        """
        self.root = root
        self.root.title("Educational Password Manager")
        self.root.geometry("700x600")
        self.root.minsize(600, 500)
        
        # Initialize database connection
        try:
            self.db = Database()
        except DatabaseError as e:
            messagebox.showerror("Database Error", f"Failed to initialize database: {e}")
            self.root.destroy()
            return
        
        # Create main UI
        self._create_widgets()
        
        # Bind cleanup on window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _create_widgets(self):
        """Create all GUI widgets and layout."""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Security warning banner at top
        self._create_warning_banner(main_frame)
        
        # Create notebook (tabbed interface)
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Create tabs
        self._create_add_entry_tab(notebook)
        self._create_list_entries_tab(notebook)
        self._create_verify_tab(notebook)
        self._create_generate_tab(notebook)
    
    def _create_warning_banner(self, parent):
        """
        Create security warning banner at top of window.
        
        Educational Note:
            This warning is crucial to remind users that MD5/MD4 are
            insecure and should never be used in production systems.
        """
        warning_frame = ttk.Frame(parent)
        warning_frame.pack(fill=tk.X, pady=(0, 5))
        
        warning_text = (
            "⚠️ SECURITY WARNING: MD5/MD4 are cryptographically BROKEN. "
            "This tool is for EDUCATIONAL PURPOSES ONLY!"
        )
        warning_label = ttk.Label(
            warning_frame,
            text=warning_text,
            foreground="red",
            font=("TkDefaultFont", 9, "bold"),
            wraplength=680
        )
        warning_label.pack(fill=tk.X)
    
    def _create_add_entry_tab(self, notebook):
        """
        Create the 'Add Entry' tab for adding new password entries.
        
        This tab allows users to:
        - Enter service name and username
        - Enter password manually OR generate one
        - Select hashing algorithm (MD5/MD4)
        - Optionally use salt for additional security
        """
        tab = ttk.Frame(notebook, padding="10")
        notebook.add(tab, text="Add Entry")
        
        # Service name
        ttk.Label(tab, text="Service Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.service_entry = ttk.Entry(tab, width=40)
        self.service_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W, pady=5)
        
        # Username
        ttk.Label(tab, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(tab, width=40)
        self.username_entry.grid(row=1, column=1, columnspan=2, sticky=tk.W, pady=5)
        
        # Password (shown as asterisks for security)
        ttk.Label(tab, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(tab, width=40, show="*")
        self.password_entry.grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=5)
        
        # Password length for generation
        ttk.Label(tab, text="Password Length:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.pass_length_var = tk.StringVar(value="16")
        self.pass_length_spinbox = ttk.Spinbox(
            tab, from_=8, to=64, width=10, textvariable=self.pass_length_var
        )
        self.pass_length_spinbox.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Generate password button
        self.generate_btn = ttk.Button(
            tab, text="Generate Password", command=self._generate_password_for_entry
        )
        self.generate_btn.grid(row=3, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Algorithm selection
        ttk.Label(tab, text="Hash Algorithm:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.algorithm_var = tk.StringVar(value="md5")
        algorithm_frame = ttk.Frame(tab)
        algorithm_frame.grid(row=4, column=1, columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Radiobutton(
            algorithm_frame, text="MD5", variable=self.algorithm_var, value="md5"
        ).pack(side=tk.LEFT)
        ttk.Radiobutton(
            algorithm_frame, text="MD4", variable=self.algorithm_var, value="md4"
        ).pack(side=tk.LEFT, padx=10)
        
        # Use salt checkbox
        self.use_salt_var = tk.BooleanVar(value=False)
        self.salt_checkbox = ttk.Checkbutton(
            tab, text="Use random salt (recommended)", variable=self.use_salt_var
        )
        self.salt_checkbox.grid(row=5, column=0, columnspan=3, sticky=tk.W, pady=5)
        
        # Add entry button
        self.add_btn = ttk.Button(tab, text="Add Entry", command=self._add_entry)
        self.add_btn.grid(row=6, column=0, columnspan=3, pady=20)
        
        # Status label for feedback
        self.add_status_label = ttk.Label(tab, text="", foreground="green")
        self.add_status_label.grid(row=7, column=0, columnspan=3, pady=5)
        
        # Educational note
        note_text = (
            "Educational Note: The password you enter will be hashed using the selected "
            "algorithm before storage. The plaintext password is NEVER stored in the database."
        )
        note_label = ttk.Label(tab, text=note_text, wraplength=500, foreground="gray")
        note_label.grid(row=8, column=0, columnspan=3, pady=10, sticky=tk.W)
    
    def _create_list_entries_tab(self, notebook):
        """
        Create the 'List Entries' tab for viewing stored entries.
        
        IMPORTANT: This tab ONLY shows service name and username.
        Passwords (even hashed) are NEVER displayed to the user.
        """
        tab = ttk.Frame(notebook, padding="10")
        notebook.add(tab, text="List Entries")
        
        # Refresh button
        refresh_btn = ttk.Button(tab, text="Refresh List", command=self._refresh_entries)
        refresh_btn.pack(pady=5)
        
        # Treeview for entries
        columns = ("Service", "Username", "Algorithm", "Created")
        self.entries_tree = ttk.Treeview(tab, columns=columns, show="headings", height=15)
        
        # Configure columns
        self.entries_tree.heading("Service", text="Service")
        self.entries_tree.heading("Username", text="Username")
        self.entries_tree.heading("Algorithm", text="Algorithm")
        self.entries_tree.heading("Created", text="Created At")
        
        self.entries_tree.column("Service", width=150)
        self.entries_tree.column("Username", width=150)
        self.entries_tree.column("Algorithm", width=80)
        self.entries_tree.column("Created", width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=self.entries_tree.yview)
        self.entries_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        self.entries_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Educational note
        note_frame = ttk.Frame(tab)
        note_frame.pack(fill=tk.X, pady=10)
        note_text = (
            "Educational Note: Passwords are NEVER displayed here. Only service names "
            "and usernames are shown. Use the 'Verify Password' tab to check passwords."
        )
        note_label = ttk.Label(note_frame, text=note_text, wraplength=500, foreground="gray")
        note_label.pack()
        
        # Load initial data
        self._refresh_entries()
    
    def _create_verify_tab(self, notebook):
        """
        Create the 'Verify Password' tab for checking passwords.
        
        This demonstrates password verification:
        1. User enters service, username, and password to verify
        2. Password is hashed using the stored algorithm and salt
        3. Hash is compared with stored hash
        4. Result is shown (match or no match)
        """
        tab = ttk.Frame(notebook, padding="10")
        notebook.add(tab, text="Verify Password")
        
        # Service name
        ttk.Label(tab, text="Service Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.verify_service_entry = ttk.Entry(tab, width=40)
        self.verify_service_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Username
        ttk.Label(tab, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.verify_username_entry = ttk.Entry(tab, width=40)
        self.verify_username_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Password to verify (hidden)
        ttk.Label(tab, text="Password to Verify:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.verify_password_entry = ttk.Entry(tab, width=40, show="*")
        self.verify_password_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Verify button
        verify_btn = ttk.Button(tab, text="Verify Password", command=self._verify_password)
        verify_btn.grid(row=3, column=0, columnspan=2, pady=20)
        
        # Result label
        self.verify_result_label = ttk.Label(tab, text="", font=("TkDefaultFont", 10, "bold"))
        self.verify_result_label.grid(row=4, column=0, columnspan=2, pady=10)
        
        # Educational note
        note_text = (
            "Educational Note: Password verification works by hashing the input password "
            "with the same algorithm and salt, then comparing with the stored hash. "
            "If they match, the password is correct. The original password cannot be recovered."
        )
        note_label = ttk.Label(tab, text=note_text, wraplength=500, foreground="gray")
        note_label.grid(row=5, column=0, columnspan=2, pady=10, sticky=tk.W)
    
    def _create_generate_tab(self, notebook):
        """
        Create the 'Generate Password' tab for creating secure passwords.
        
        This tab demonstrates password generation best practices:
        - Configurable length
        - Character type options (uppercase, lowercase, digits, symbols)
        - Strength assessment
        """
        tab = ttk.Frame(notebook, padding="10")
        notebook.add(tab, text="Generate Password")
        
        # Password length
        ttk.Label(tab, text="Password Length:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.gen_length_var = tk.StringVar(value="16")
        length_spinbox = ttk.Spinbox(
            tab, from_=8, to=64, width=10, textvariable=self.gen_length_var
        )
        length_spinbox.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Character type options
        ttk.Label(tab, text="Include:").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        options_frame = ttk.Frame(tab)
        options_frame.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        self.use_uppercase_var = tk.BooleanVar(value=True)
        self.use_lowercase_var = tk.BooleanVar(value=True)
        self.use_digits_var = tk.BooleanVar(value=True)
        self.use_symbols_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(
            options_frame, text="Uppercase (A-Z)", variable=self.use_uppercase_var
        ).pack(anchor=tk.W)
        ttk.Checkbutton(
            options_frame, text="Lowercase (a-z)", variable=self.use_lowercase_var
        ).pack(anchor=tk.W)
        ttk.Checkbutton(
            options_frame, text="Digits (0-9)", variable=self.use_digits_var
        ).pack(anchor=tk.W)
        ttk.Checkbutton(
            options_frame, text="Symbols (!@#$...)", variable=self.use_symbols_var
        ).pack(anchor=tk.W)
        
        # Generate button
        generate_btn = ttk.Button(
            tab, text="Generate Password", command=self._generate_password_standalone
        )
        generate_btn.grid(row=2, column=0, columnspan=2, pady=20)
        
        # Generated password display (read-only)
        ttk.Label(tab, text="Generated Password:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.generated_password_var = tk.StringVar()
        self.generated_password_entry = ttk.Entry(
            tab, width=40, textvariable=self.generated_password_var, state="readonly"
        )
        self.generated_password_entry.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Copy button
        copy_btn = ttk.Button(tab, text="Copy to Clipboard", command=self._copy_password)
        copy_btn.grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # Strength indicator
        ttk.Label(tab, text="Strength:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.strength_label = ttk.Label(tab, text="")
        self.strength_label.grid(row=5, column=1, sticky=tk.W, pady=5)
        
        # Educational note
        note_text = (
            "Educational Note: Strong passwords use multiple character types and sufficient "
            "length. This generator uses Python's 'secrets' module which provides "
            "cryptographically secure random numbers suitable for password generation."
        )
        note_label = ttk.Label(tab, text=note_text, wraplength=500, foreground="gray")
        note_label.grid(row=6, column=0, columnspan=2, pady=20, sticky=tk.W)
    
    # =========================================================================
    # Event Handlers (use existing modules for business logic)
    # =========================================================================
    
    def _generate_password_for_entry(self):
        """
        Generate a password and fill the password entry field.
        
        Uses the password_generator module (no duplicate logic).
        """
        try:
            length = int(self.pass_length_var.get())
            # Use existing password_generator module
            password = generate_password(
                length=length,
                use_uppercase=True,
                use_lowercase=True,
                use_digits=True,
                use_symbols=True
            )
            # Set password in entry (user can see it briefly before adding)
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, password)
            self.add_status_label.config(
                text="Password generated! Save this entry immediately.",
                foreground="blue"
            )
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def _add_entry(self):
        """
        Add a new password entry to the database.
        
        Uses existing modules:
        - hash_utils.hash_password() for hashing
        - hash_utils.generate_salt() for salt generation
        - database.Database.add_entry() for storage
        
        The password is hashed immediately and the plaintext is discarded.
        """
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        algorithm = self.algorithm_var.get()
        use_salt = self.use_salt_var.get()
        
        # Validation
        if not service:
            messagebox.showwarning("Validation Error", "Service name is required.")
            return
        
        if not username:
            messagebox.showwarning("Validation Error", "Username is required.")
            return
        
        if not password:
            messagebox.showwarning("Validation Error", "Password is required.")
            return
        
        try:
            # Generate salt if requested (using existing hash_utils module)
            salt = generate_salt() if use_salt else None
            
            # Hash the password (using existing hash_utils module)
            password_hash = hash_password(password, algorithm, salt)
            
            # Store in database (using existing database module)
            entry_id = self.db.add_entry(service, username, password_hash, algorithm, salt)
            
            if entry_id:
                self.add_status_label.config(
                    text=f"✓ Entry added successfully! (ID: {entry_id})",
                    foreground="green"
                )
                # Clear fields
                self.service_entry.delete(0, tk.END)
                self.username_entry.delete(0, tk.END)
                self.password_entry.delete(0, tk.END)
                # Refresh list
                self._refresh_entries()
            else:
                self.add_status_label.config(
                    text="✗ Entry already exists for this service/username.",
                    foreground="red"
                )
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except DatabaseError as e:
            messagebox.showerror("Database Error", str(e))
    
    def _refresh_entries(self):
        """
        Refresh the entries list from database.
        
        Uses existing database.Database.get_all_entries() method.
        IMPORTANT: Only displays service and username, NEVER passwords.
        """
        # Clear current items
        for item in self.entries_tree.get_children():
            self.entries_tree.delete(item)
        
        try:
            # Get entries using existing database module
            entries = self.db.get_all_entries()
            
            for entry in entries:
                # entry = (id, service, username, password_hash, algorithm, salt, created_at)
                # We only display service, username, algorithm, and created_at
                # Password hash is NEVER displayed
                entry_id, service, username, _, algorithm, _, created_at = entry
                self.entries_tree.insert(
                    "", tk.END, values=(service, username, algorithm.upper(), created_at)
                )
        except DatabaseError as e:
            messagebox.showerror("Database Error", f"Failed to load entries: {e}")
    
    def _verify_password(self):
        """
        Verify a password against the stored hash.
        
        Uses existing modules:
        - database.Database.get_entry() to retrieve stored hash
        - hash_utils.hash_password() to hash the input password
        
        The verification is done by comparing hashes, not plaintext.
        """
        service = self.verify_service_entry.get().strip()
        username = self.verify_username_entry.get().strip()
        password = self.verify_password_entry.get()
        
        # Validation
        if not service or not username:
            messagebox.showwarning("Validation Error", "Service and username are required.")
            return
        
        if not password:
            messagebox.showwarning("Validation Error", "Password to verify is required.")
            return
        
        try:
            # Get entry from database (using existing database module)
            entry = self.db.get_entry(service, username)
            
            if not entry:
                self.verify_result_label.config(
                    text="✗ No entry found for this service/username.",
                    foreground="red"
                )
                return
            
            # Extract stored hash info
            _, _, _, stored_hash, stored_algo, salt_hex, _ = entry
            
            # Convert salt from hex string back to bytes
            # Check for empty string as well as None since database may store empty strings
            salt = bytes.fromhex(salt_hex) if salt_hex and salt_hex.strip() else None
            
            # Hash the provided password with same algorithm and salt
            # (using existing hash_utils module)
            password_hash = hash_password(password, stored_algo, salt)
            
            # Compare hashes
            if password_hash == stored_hash:
                self.verify_result_label.config(
                    text="✓ Password verified successfully! Hashes match.",
                    foreground="green"
                )
            else:
                self.verify_result_label.config(
                    text="✗ Password verification failed. Hashes do not match.",
                    foreground="red"
                )
            
            # Clear password field for security
            self.verify_password_entry.delete(0, tk.END)
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except DatabaseError as e:
            messagebox.showerror("Database Error", str(e))
    
    def _generate_password_standalone(self):
        """
        Generate a password in the Generate tab.
        
        Uses existing password_generator module (no duplicate logic).
        """
        try:
            length = int(self.gen_length_var.get())
            
            # Check that at least one character type is selected
            if not any([
                self.use_uppercase_var.get(),
                self.use_lowercase_var.get(),
                self.use_digits_var.get(),
                self.use_symbols_var.get()
            ]):
                messagebox.showwarning(
                    "Validation Error",
                    "At least one character type must be selected."
                )
                return
            
            # Use existing password_generator module
            password = generate_password(
                length=length,
                use_uppercase=self.use_uppercase_var.get(),
                use_lowercase=self.use_lowercase_var.get(),
                use_digits=self.use_digits_var.get(),
                use_symbols=self.use_symbols_var.get()
            )
            
            # Display generated password
            self.generated_password_var.set(password)
            
            # Show strength (using existing password_generator module)
            _, strength_desc = estimate_password_strength(password)
            self.strength_label.config(text=strength_desc)
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def _copy_password(self):
        """Copy generated password to clipboard."""
        password = self.generated_password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("No Password", "Generate a password first.")
    
    def _on_closing(self):
        """Handle window close event."""
        try:
            self.db.close()
        except Exception:
            pass  # Ignore errors on close
        self.root.destroy()


def main():
    """
    Main entry point for the Password Manager GUI.
    
    Creates the Tkinter root window and initializes the GUI application.
    """
    root = tk.Tk()
    
    # Create and run the application
    app = PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
