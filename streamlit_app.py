# ==========================================
# 🔐 Secure App – Cybersecurity Demonstration
# Streamlit version (SHA-256, no Flask, no bcrypt)
# ==========================================

import streamlit as st
import hashlib
import json
import os
import re
import datetime
from cryptography.fernet import Fernet

# ===============================
# INITIAL SETUP
# ===============================

DB_FILE = "users.json"
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump({}, f)

# ---- persistent encryption key ----
if "fernet" not in st.session_state:
    if not os.path.exists("secret.key"):
        with open("secret.key", "wb") as keyfile:
            keyfile.write(Fernet.generate_key())
    with open("secret.key", "rb") as keyfile:
        key = keyfile.read()
    st.session_state.fernet = Fernet(key)

fernet = st.session_state.fernet

# ===============================
# HELPERS
# ===============================
def load_users():
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_users(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)

def log_action(username, action):
    with open("audit_log.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} | {username} | {action}\n")

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[0-9]", password):
        return False, "Password must include at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must include a special character."
    return True, "Strong password."

def validate_input(text):
    blacklist = ["<script>", "SELECT", "DROP", "--", ";", "INSERT"]
    for word in blacklist:
        if word.lower() in text.lower():
            return False
    return True

def encrypt_data(data):
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    try:
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return "Decryption failed."

# ===============================
# STREAMLIT UI
# ===============================

st.set_page_config(page_title="Secure App", page_icon="🔐", layout="centered")
st.title("🔐 Secure Cybersecurity Demo App")

menu = ["Register", "Login", "Profile", "Encrypt/Decrypt", "File Upload", "Error Handling"]
choice = st.sidebar.selectbox("Menu", menu)

# Maintain session
if "current_user" not in st.session_state:
    st.session_state.current_user = None

# -------------------------------
# REGISTER
# -------------------------------
if choice == "Register":
    st.header("📝 Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        users = load_users()
        if username in users:
            st.error("Username already exists.")
        else:
            valid, msg = validate_password(password)
            if not valid:
                st.error(msg)
            else:
                users[username] = {"password": hash_password(password), "data": ""}
                save_users(users)
                log_action(username, "Registered successfully")
                st.success("Registration successful!")

# -------------------------------
# LOGIN
# -------------------------------
elif choice == "Login":
    st.header("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        users = load_users()
        if username in users and users[username]["password"] == hash_password(password):
            st.session_state.current_user = username
            log_action(username, "Logged in")
            st.success(f"Welcome, {username}!")
        else:
            st.error("Invalid credentials.")

# -------------------------------
# PROFILE
# -------------------------------
elif choice == "Profile":
    if not st.session_state.current_user:
        st.warning("You must log in first.")
    else:
        st.header("👤 Profile Management")
        new_data = st.text_input("Update your profile info:")

        if st.button("Update Profile"):
            if validate_input(new_data):
                users = load_users()
                encrypted_info = encrypt_data(new_data)
                users[st.session_state.current_user]["data"] = encrypted_info
                save_users(users)
                log_action(st.session_state.current_user, "Profile updated")
                st.success("Profile updated & encrypted!")
            else:
                st.error("Invalid input detected.")
        
        if st.button("View Decrypted Data"):
            users = load_users()
            enc = users[st.session_state.current_user]["data"]
            if enc:
                st.info(f"Decrypted: {decrypt_data(enc)}")
            else:
                st.warning("No data found.")

        if st.button("Logout"):
            log_action(st.session_state.current_user, "Logged out")
            st.session_state.current_user = None
            st.success("Logged out successfully!")

# -------------------------------
# ENCRYPT/DECRYPT TEST
# -------------------------------
elif choice == "Encrypt/Decrypt":
    st.header("🧩 Encryption Demo")
    data = st.text_input("Enter text to encrypt:")
    if st.button("Encrypt"):
        if data:
            encrypted = encrypt_data(data)
            st.code(f"Encrypted: {encrypted}")
            st.code(f"Decrypted: {decrypt_data(encrypted)}")
        else:
            st.warning("Please enter some text.")

# -------------------------------
# FILE UPLOAD VALIDATION
# -------------------------------
elif choice == "File Upload":
    st.header("📂 File Upload Validation")
    uploaded = st.file_uploader("Upload a file")
    if uploaded:
        if not uploaded.name.lower().endswith((".txt", ".pdf", ".png", ".jpg")):
            st.error("❌ File type not allowed!")
        else:
            st.success(f"✅ {uploaded.name} uploaded successfully!")

# -------------------------------
# ERROR HANDLING
# -------------------------------
elif choice == "Error Handling":
    st.header("⚙️ Error Handling Test")
    a = st.number_input("Enter number A:", step=1)
    b = st.number_input("Enter number B:", step=1)
    if st.button("Divide"):
        try:
            result = a / b
            st.success(f"Result: {result}")
        except Exception:
            st.error("Error handled safely — no crash occurred.")
