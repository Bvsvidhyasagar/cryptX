import json
import base64
from Crypto.Cipher import AES
import os

# File to store passwords
PASSWORD_FILE = "passwords.json"

# AES Key (must be 16, 24, or 32 bytes long)
SECRET_KEY = b'16ByteSecretKey!'

# Function to pad passwords to make them AES-compatible (16 bytes)
def pad_password(password):
    return password + (16 - len(password) % 16) * ' '

# Encrypt the password
def encrypt_password(password):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad_password(password).encode())
    return base64.b64encode(encrypted_text).decode()

# Decrypt the password
def decrypt_password(encrypted_password):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_password)).decode().strip()
    return decrypted_text

# Save password to JSON file
def save_password(name, encrypted_password):
    data = load_passwords()
    data[name] = encrypted_password

    with open(PASSWORD_FILE, "w") as file:
        json.dump(data, file, indent=4)

    print(f"Password saved for {name}!")

# Retrieve password from JSON file
def get_password(name):
    data = load_passwords()
    return data.get(name, None)

# Load passwords from JSON file
def load_passwords():
    if not os.path.exists(PASSWORD_FILE):
        return {}
    
    with open(PASSWORD_FILE, "r") as file:
        return json.load(file)

if __name__ == "__main__":
    while True:
        print("\n1. Encrypt & Store Password\n2. Retrieve & Decrypt Password\n3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            name = input("Enter a name for the password (e.g., Gmail, Facebook): ")
            password = input("Enter your password: ")
            encrypted_pass = encrypt_password(password)
            save_password(name, encrypted_pass)

        elif choice == '2':
            name = input("Enter the name to retrieve the password: ")
            encrypted_pass = get_password(name)
            if encrypted_pass:
                decrypted_pass = decrypt_password(encrypted_pass)
                print(f"Decrypted Password: {decrypted_pass}")
            else:
                print("No password found!")

        elif choice == '3':
            print("Exiting...")
            break

        else:
            print("Invalid choice! Please select again.")

