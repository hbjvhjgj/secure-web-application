import streamlit as st
import hashlib
import re
import json
import base64
import datetime

# ---------- Helper Functions ----------

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email)

def is_strong_password(password):
    return len(password) >= 8 and any(c.isdigit() for c in password) and any(c.isalpha() for c in password)

def encrypt_data(data):
    return base64.b64encode(data.encode()).decode()

def decrypt_data(data):
    return base64.b64decode(data.encode()).decode()

def load_users():
    try:
        with open("users.json", "r") as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

def log_action(action):
    with open("audit_log.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} - {action}\n")

# ---------- Global Error Handling ----------
try:
    # ---------- App Logic ----------
    st.title("Secure Cybersecurity Demo App")

    users = load_users()

    # Initialize session state
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False
    if "username" not in st.session_state:
        st.session_state["username"] = None
    if "login_attempts" not in st.session_state:
        st.session_state["login_attempts"] = 0
    if "account_locked" not in st.session_state:
        st.session_state["account_locked"] = False

    menu = ["Home", "Register", "Login", "Profile", "Encrypt/Decrypt", "Logout"]
    choice = st.sidebar.selectbox("Menu", menu)

    # ---------- Registration ----------
    if choice == "Register":
        st.subheader("User Registration")

        new_username = st.text_input("Choose a Username")
        new_email = st.text_input("Enter your Email")
        new_password = st.text_input("Choose a Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")

        if st.button("Register"):
            if new_username in users:
                st.error("Username already exists.")
            elif not is_valid_email(new_email):
                st.error("Invalid email format.")
            elif not is_strong_password(new_password):
                st.error("Password must be at least 8 characters, contain letters and numbers.")
            elif new_password != confirm_password:
                st.error("Passwords do not match.")
            else:
                hashed_password = hash_password(new_password)
                users[new_username] = {"email": new_email, "password": hashed_password}
                save_users(users)
                log_action(f"User registered: {new_username}")
                st.success("Registration successful!")

    # ---------- Login ----------
    elif choice == "Login":
        st.subheader("User Login")

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.session_state["account_locked"]:
            st.error("Account locked due to too many failed attempts.")
        else:
            if st.button("Login"):
                if username in users:
                    hashed_input = hash_passwor
