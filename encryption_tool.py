import hashlib
import base64
import os

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

def menu():
    print("\n=== Basic Encryption & Hashing Tool ===")
    print("1. SHA-256 Hash")
    print("2. SHA-512 Hash")
    print("3. Base64 Encode")
    print("4. Base64 Decode")
    print("5. Generate Salt")
    print("6. Salt + Hash Password")
    print("7. Exit")
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
            except Exception:
                print("Invalid Base64 input.")

        elif choice == "5":
            print("Generated Salt:", generate_salt())

        elif choice == "6":
            password = input("Enter password: ")
            salt = input("Enter salt (or press Enter to generate a new one): ")

            if salt.strip() == "":
                salt = generate_salt()
                print("Generated Salt:", salt)

            print("Salted Hash:", salted_hash(password, salt))

        elif choice == "7":
            print("Goodbye!")
            break

        else:
            print("Invalid option. Try again.")

if __name__ == "__main__":
    main()
