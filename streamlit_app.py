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

# ---------- App Logic ----------

st.title("🔐 Secure Cybersecurity Demo App")

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
    st.subheader("🧾 User Registration")

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
            st.success("✅ Registration successful!")

# ---------- Login ----------
elif choice == "Login":
    st.subheader("🔑 User Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.session_state["account_locked"]:
        st.error("Account locked due to too many failed attempts.")
    else:
        if st.button("Login"):
            if username in users:
                hashed_input = hash_password(password)
                if hashed_input == users[username]["password"]:
                    st.session_state["logged_in"] = True
                    st.session_state["username"] = username
                    st.session_state["login_attempts"] = 0
                    log_action(f"User logged in: {username}")
                    st.success(f"Welcome, {username}!")
                    st.rerun()
                else:
                    st.session_state["login_attempts"] += 1
                    remaining = 5 - st.session_state["login_attempts"]
                    st.error(f"Incorrect password. {remaining} attempts left.")
            else:
                st.error("User not found.")

            if st.session_state["login_attempts"] >= 5:
                st.session_state["account_locked"] = True
                st.error("Too many failed attempts. Account locked.")

# ---------- Profile ----------
elif choice == "Profile":
    if st.session_state["logged_in"]:
        st.subheader("👤 Profile Page")
        st.write(f"Username: {st.session_state['username']}")
        st.write(f"Email: {users[st.session_state['username']]['email']}")

        new_email = st.text_input("Update Email")
        if st.button("Update Email"):
            if not is_valid_email(new_email):
                st.error("Invalid email format.")
            else:
                users[st.session_state["username"]]["email"] = new_email
                save_users(users)
                log_action(f"User updated email: {st.session_state['username']}")
                st.success("Email updated successfully!")

    else:
        st.warning("Please log in first.")

# ---------- Encrypt / Decrypt ----------
elif choice == "Encrypt/Decrypt":
    st.subheader("🔐 Encrypt / Decrypt Data")

    data = st.text_area("Enter text")
    if st.button("Encrypt"):
        if data:
            encrypted = encrypt_data(data)
            st.write("Encrypted Data:", encrypted)
            log_action(f"Data encrypted by {st.session_state.get('username', 'guest')}")
        else:
            st.warning("Please enter text to encrypt.")

    if st.button("Decrypt"):
        if data:
            try:
                decrypted = decrypt_data(data)
                st.write("Decrypted Data:", decrypted)
                log_action(f"Data decrypted by {st.session_state.get('username', 'guest')}")
            except:
                st.error("Invalid encrypted data.")
        else:
            st.warning("Please enter text to decrypt.")

# ---------- Logout ----------
elif choice == "Logout":
    if st.session_state["logged_in"]:
        log_action(f"User logged out: {st.session_state['username']}")
        st.session_state["logged_in"] = False
        st.session_state["username"] = None
        st.success("You have been logged out.")
    else:
        st.info("No user logged in.")

# ---------- Home ----------
else:
    st.info("Welcome to the Secure App! Use the sidebar to navigate.")
