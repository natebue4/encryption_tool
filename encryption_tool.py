import hashlib
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ----------------------
# EXISTING FUNCTIONS
# ----------------------

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def sha512_hash(text):
    return hashlib.sha512(text.encode()).hexdigest()

def base64_encode(text):
    return base64.b64encode(text.encode()).decode()

def base64_decode(text):
    return base64.b64decode(text.encode()).decode()

def generate_salt(length=16):
    return base64.b64encode(os.urandom(length)).decode()

def salted_hash(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

# ----------------------
# AES ENCRYPTION SECTION
# ----------------------

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive AES key from password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=salt,
        iterations=200000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

def aes_encrypt(password: str, plaintext: str):
    """Encrypt plaintext using AES-256-GCM."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

def aes_decrypt(password: str, salt_b64: str, nonce_b64: str, ciphertext_b64: str):
    """Decrypt AES-256-GCM ciphertext."""
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

# ----------------------
# MENU SYSTEM
# ----------------------

def menu():
    print("\n=== Encryption Tool 2.0 ===")
    print("1. SHA-256 Hash")
    print("2. SHA-512 Hash")
    print("3. Base64 Encode")
    print("4. Base64 Decode")
    print("5. Generate Salt")
    print("6. Salt + Hash Password")
    print("7. AES Encrypt Text")
    print("8. AES Decrypt Text")
    print("9. Exit")
    return input("Choose an option: ")

def main():
    while True:
        choice = menu()

        if choice == "1":
            text = input("Enter text to hash (SHA-256): ")
            print("Hash:", sha256_hash(text))

        elif choice == "2":
            text = input("Enter text to hash (SHA-512): ")
            print("Hash:", sha512_hash(text))

        elif choice == "3":
            text = input("Enter text for Base64 encoding: ")
            print("Encoded:", base64_encode(text))

        elif choice == "4":
            text = input("Enter Base64 to decode: ")
            try:
                print("Decoded:", base64_decode(text))
            except:
                print("Invalid Base64 input.")

        elif choice == "5":
            print("Generated Salt:", generate_salt())

        elif choice == "6":
            password = input("Enter password: ")
            salt = input("Enter salt (or press Enter to generate new): ")
            if salt.strip() == "":
                salt = generate_salt()
                print("Generated Salt:", salt)
            print("Salted Hash:", salted_hash(password, salt))

        elif choice == "7":  # AES Encrypt
            password = input("Enter password for encryption: ")
            text = input("Enter text to encrypt: ")
            encrypted = aes_encrypt(password, text)
            print("\n=== AES ENCRYPTED OUTPUT ===")
            print("Salt:", encrypted["salt"])
            print("Nonce:", encrypted["nonce"])
            print("Ciphertext:", encrypted["ciphertext"])

        elif choice == "8":  # AES Decrypt
            password = input("Enter password for decryption: ")
            salt = input("Salt: ")
            nonce = input("Nonce: ")
            ciphertext = input("Ciphertext: ")
            try:
                decrypted = aes_decrypt(password, salt, nonce, ciphertext)
                print("Decrypted Text:", decrypted)
            except Exception:
                print("Decryption failed. Incorrect password or data.")

        elif choice == "9":
            print("Goodbye!")
            break

        else:
            print("Invalid option. Try again.")

if __name__ == "__main__":
    main()
