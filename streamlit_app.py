# ==========================================
# 🔐 Secure App - Cybersecurity Demonstration
# No Flask used (console-based app)
# Works in Google Colab or any IDE
# ==========================================

import bcrypt
import re
import json
from cryptography.fernet import Fernet
import datetime
import os

# -------------------------------
# Initialize encryption key
# -------------------------------
key = Fernet.generate_key()
fernet = Fernet(key)

# -------------------------------
# Simulated Database (JSON file)
# -------------------------------
DB_FILE = "users.json"
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump({}, f)

# -------------------------------
# Helper functions
# -------------------------------
def load_users():
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_users(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)

def log_action(username, action):
    with open("audit_log.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} | {username} | {action}\n")

# -------------------------------
# 1. Password Strength Validation
# -------------------------------
def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[0-9]", password):
        return False, "Password must include at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must include a special character."
    return True, "Strong password."

# -------------------------------
# 2. Input Validation
# -------------------------------
def validate_input(text):
    # Prevent script or SQL injection
    blacklist = ["<script>", "SELECT", "DROP", "--", ";", "INSERT"]
    for word in blacklist:
        if word.lower() in text.lower():
            return False
    return True

# -------------------------------
# 3. Register User
# -------------------------------
def register_user(username, password):
    users = load_users()
    if username in users:
        return "Username already exists."

    valid, msg = validate_password(password)
    if not valid:
        return msg

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users[username] = {
        "password": hashed_pw.decode(),
        "data": "",
    }
    save_users(users)
    log_action(username, "Registered successfully")
    return "Registration successful!"

# -------------------------------
# 4. Login User
# -------------------------------
current_user = None

def login_user(username, password):
    global current_user
    users = load_users()

    if username not in users:
        return "Invalid username or password."

    stored_hash = users[username]["password"].encode()
    if bcrypt.checkpw(password.encode(), stored_hash):
        current_user = username
        log_action(username, "Logged in successfully")
        return f"Welcome, {username}!"
    else:
        return "Invalid username or password."

# -------------------------------
# 5. Encrypt / Decrypt Data
# -------------------------------
def encrypt_data(data):
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    try:
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return "Decryption failed."

# -------------------------------
# 6. Profile Update (with validation)
# -------------------------------
def update_profile(new_data):
    global current_user
    if not current_user:
        return "You must log in first."

    if not validate_input(new_data):
        return "Invalid input detected."

    users = load_users()
    encrypted_info = encrypt_data(new_data)
    users[current_user]["data"] = encrypted_info
    save_users(users)
    log_action(current_user, "Profile updated")
    return "Profile updated and encrypted successfully!"

# -------------------------------
# 7. View Profile (decrypt data)
# -------------------------------
def view_profile():
    global current_user
    if not current_user:
        return "You must log in first."

    users = load_users()
    encrypted_data = users[current_user]["data"]
    if not encrypted_data:
        return "No profile data found."
    decrypted = decrypt_data(encrypted_data)
    return f"Your decrypted profile data: {decrypted}"

# -------------------------------
# 8. Logout
# -------------------------------
def logout():
    global current_user
    if not current_user:
        return "No user is logged in."
    log_action(current_user, "Logged out")
    current_user = None
    return "Logged out successfully."

# -------------------------------
# 9. File Upload Validation (simulated)
# -------------------------------
def validate_file_upload(filename):
    allowed_extensions = [".txt", ".pdf", ".jpg", ".png"]
    if not any(filename.endswith(ext) for ext in allowed_extensions):
        return "File type not allowed!"
    return "File uploaded successfully."

# -------------------------------
# 10. Error Handling Example
# -------------------------------
def divide_numbers(a, b):
    try:
        return a / b
    except Exception:
        return "Error: invalid operation."

# -------------------------------
# Main Menu (Console)
# -------------------------------
def main():
    while True:
        print("\n===== Secure App Menu =====")
        print("1. Register")
        print("2. Login")
        print("3. Update Profile")
        print("4. View Profile")
        print("5. Encrypt/Decrypt Test")
        print("6. File Upload Validation")
        print("7. Safe Division (Error Handling)")
        print("8. Logout")
        print("9. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            u = input("Enter username: ")
            p = input("Enter password: ")
            print(register_user(u, p))

        elif choice == "2":
            u = input("Username: ")
            p = input("Password: ")
            print(login_user(u, p))

        elif choice == "3":
            data = input("Enter profile info: ")
            print(update_profile(data))

        elif choice == "4":
            print(view_profile())

        elif choice == "5":
            data = input("Enter text to encrypt: ")
            encrypted = encrypt_data(data)
            print(f"Encrypted: {encrypted}")
            print(f"Decrypted: {decrypt_data(encrypted)}")

        elif choice == "6":
            f = input("Enter filename (e.g. test.exe): ")
            print(validate_file_upload(f))

        elif choice == "7":
            a = int(input("Enter number a: "))
            b = int(input("Enter number b: "))
            print(divide_numbers(a, b))

        elif choice == "8":
            print(logout())

        elif choice == "9":
            print("Exiting app...")
            break

        else:
            print("Invalid choice!")

# Run the program
if __name__ == "__main__":
    main()
