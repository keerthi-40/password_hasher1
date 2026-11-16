
import sqlite3
import base64
import os
import sys
from getpass import getpass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Security Configuration
DB_NAME = "vault.db"
ph = PasswordHasher()
def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a Fernet-compatible key from master password."""

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = base64.urlsafe_b64encode(
        kdf.derive(master_password.encode())
    )

    return key


# Database Initialization
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                master_hash TEXT,
                salt BLOB
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                site TEXT,
                username TEXT,
                encrypted_password TEXT
            )
        """)

        conn.commit()


# Account Setup
def setup_account():
    print("--- Initialize Your Vault ---")

    mp = getpass("Create a Master Password: ")
    confirm = getpass("Confirm Master Password: ")

    if mp != confirm:
        print("Passwords do not match!")
        return

    salt = os.urandom(16)
    master_hash = ph.hash(mp)

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute(
            "INSERT INTO config VALUES (?, ?)",
            (master_hash, salt)
        )

    print("Vault initialized successfully.")


# Retrieve Vault Configuration
def get_vault_config():
    with sqlite3.connect(DB_NAME) as conn:
        return conn.execute(
            "SELECT master_hash, salt FROM config"
        ).fetchone()
        
        
def add_password(fernet):
    
    site = input("Enter Website: ")
    user = input("Enter Username: ")hiii
    pwd = getpass("Enter Password to Save: ")

    encrypted = fernet.encrypt(pwd.encode()).decode()

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute(
            "INSERT INTO secrets VALUES (?, ?, ?)",
            (site, user, encrypted)
        )

    print(f"Stored credentials for {site}!")


# View Saved Passwords
def list_passwords(fernet):

    with sqlite3.connect(DB_NAME) as conn:
        rows = conn.execute(
            "SELECT site, username, encrypted_password FROM secrets"
        ).fetchall()

    if not rows:
        print("No passwords saved yet.")
        return

    print("\n--- Your Saved Passwords ---")

    for site, user, enc_pwd in rows:
        try:
            decrypted = fernet.decrypt(
                enc_pwd.encode()
            ).decode()

            print(
                f"Site: {site:15} | "
                f"User: {user:15} | "
                f"Password: {decrypted}"
            )

        except Exception:
            print(f"Error decrypting {site}")