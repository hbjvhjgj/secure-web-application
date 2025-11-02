import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
import re
from datetime import datetime

# ================== Helper Functions ==================

# Generate or load encryption key
def load_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    with open("secret.key", "rb") as key_file:
        return key_file.read()

key = load_key()
fernet = Fernet(key)

# Load users
def load_users():
    if os.path.exists("users.json"):
        with open("users.json", "r") as file:
            return json.load(file)
    return {}

# Save users
def save_users(users):
    with open("users.json", "w") as file:
        json.dump(users, file, indent=4)

# Password hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Password strength validation
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# Audit logging
def log_activity(action, username="Unknown"):
    with open("audit_log.txt", "a") as log_file:
        log_file.write(f"{datetime.now()} - {username} - {action}\n")

# ================== Registration ==================
def register_user():
    st.subheader("User Registration")
    username = st.text_input("Enter a username:")
    password = st.text_input("Enter a strong password:", type="password")

    if st.button("Register"):
        users = load_users()

        if not username or not password:
            st.warning("Please fill all fields.")
            return

        if not is_strong_password(password):
            st.error("Password must be at least 8 characters long and include a number and a special symbol.")
            return

        if username in users:
            st.error("Username already exists. Choose another one.")
            return

        # Input validation
        if "<" in username or ">" in username or "'" in username or '"' in username:
            st.error("Invalid characters in username.")
            return

        hashed_pw = hash_password(password)
        users[username] = {"password": hashed_pw, "data": ""}
        save_users(users)
        st.success("✅ Registration successful!")
        log_activity("Registered new user", username)

# ================== Login ==================
def login_user():
    st.subheader("User Login")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    if st.button("Login"):
        users = load_users()
        if username in users:
            stored_hash = users[username]["password"]
            if hash_password(password) == stored_hash:
                st.session_state["logged_in"] = True
                st.session_state["username"] = username
                st.success(f"Welcome, {username}!")
                log_activity("User logged in", username)
                st.rerun()
            else:
                st.error("Invalid credentials.")
        else:
            st.error("User not found.")

# ================== Profile (Encrypted Data) ==================
def profile_page():
    st.subheader("User Profile")

    if "logged_in" not in st.session_state or not st.session_state["logged_in"]:
        st.warning("Please login first.")
        return

    username = st.session_state["username"]
    users = load_users()

    profile_info = st.text_area("Update your profile info:")

    if st.button("Update Profile"):
        encrypted_data = fernet.encrypt(profile_info.encode()).decode()
        users[username]["data"] = encrypted_data
        save_users(users)
        st.success("Profile updated successfully (encrypted).")
        log_activity("Profile updated", username)

    if st.button("View Decrypted Data"):
        encrypted_data = users[username]["data"]
        if encrypted_data:
            decrypted_data = fernet.decrypt(encrypted_data.encode()).decode()
            st.info(f"Decrypted data: {decrypted_data}")
        else:
            st.warning("No data found.")

# ================== Encryption / Decryption ==================
def encryption_page():
    st.subheader("Encrypt / Decrypt Test")
    text = st.text_input("Enter text to encrypt:")

    if st.button("Encrypt"):
        if text:
            encrypted = fernet.encrypt(text.encode()).decode()
            decrypted = fernet.decrypt(encrypted.encode()).decode()
            st.write(f"🔒 Encrypted: {encrypted}")
            st.write(f"🔓 Decrypted: {decrypted}")
        else:
            st.warning("Enter some text first.")

# ================== Error Handling ==================
def error_handling_page():
    st.subheader("Error Handling Test")

    a = st.text_input("Enter number A:")
    b = st.text_input("Enter number B:")

    if st.button("Divide"):
        try:
            result = float(a) / float(b)
            st.success(f"Result = {result}")
        except ZeroDivisionError:
            st.error("Cannot divide by zero.")
        except ValueError:
            st.error("Please enter valid numbers.")
        except Exception as e:
            st.error("An error occurred (handled safely).")
            log_activity(f"Error: {str(e)}")

# ================== File Upload Validation ==================
def file_upload_page():
    st.subheader("Secure File Upload")
    file = st.file_uploader("Upload file", type=["txt", "pdf", "png", "jpg"])
    if file:
        st.success(f"Uploaded file: {file.name}")
        log_activity("File uploaded", st.session_state.get("username", "Guest"))

# ================== Logout ==================
def logout():
    if st.button("Logout"):
        st.session_state.clear()
        st.success("You have been logged out.")
        log_activity("User logged out")
        st.rerun()

# ================== Main App ==================
def main():
    st.title("🔐 Secure Cybersecurity App (SHA-256 Version)")

    menu = ["Login", "Register", "Profile", "Encrypt/Decrypt", "Error Handling", "File Upload"]
    choice = st.sidebar.selectbox("Menu", menu)

    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False

    if choice == "Register":
        register_user()

    elif choice == "Login":
        if not st.session_state["logged_in"]:
            login_user()
        else:
            st.success(f"Welcome back, {st.session_state['username']}!")
            logout()

    elif choice == "Profile":
        if st.session_state["logged_in"]:
            profile_page()
            logout()
        else:
            st.warning("Please login first.")

    elif choice == "Encrypt/Decrypt":
        if st.session_state["logged_in"]:
            encryption_page()
            logout()
        else:
            st.warning("Please login first.")

    elif choice == "Error Handling":
        error_handling_page()

    elif choice == "File Upload":
        file_upload_page()

if __name__ == "__main__":
    main()
