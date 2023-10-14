import streamlit as st
import sqlite3
import hashlib
import os

conn = sqlite3.connect("auth.db")
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')
conn.commit()

def user_exists(username):
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    return cursor.fetchone() is not None

def verify_password(username, password):
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    if user_data:
        hashed_password = user_data[0]
        return hashlib.sha256(password.encode()).hexdigest() == hashed_password
    return False

def signup():
    st.title("Signup")
    new_username = st.text_input("Username (Signup)")
    new_password = st.text_input("Password (Signup)", type="password")
    if st.button("Sign Up"):
        if user_exists(new_username):
            st.error("Username already exists. Please choose a different one.")
        else:
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_username, hashed_password))
            conn.commit()
            st.success("Signup successful! You can now log in.")

def login():
    st.title("Login")
    username = st.text_input("Username (Login)")
    password = st.text_input("Password (Login)", type="password")
    if st.button("Log In"):
        if verify_password(username, password):
            st.success(f"Welcome, {username}!")
            st.session_state.logged_in = True  

def file_upload_and_display():
    st.title("Text File Code Viewer")
    uploaded_file = st.file_uploader("Upload a text file", type=["txt"])
    if uploaded_file is not None:
        directory_path = r"F:\URI\Week 2\textfiles"  
        file_path, file_contents = save_uploaded_file(uploaded_file, directory_path)
        file_contents = file_contents.decode("utf-8")

        file_contents = file_contents.replace("\r\n", "\n").replace("\r", "\n")

        st.subheader("File Content:")
        st.code(file_contents, language="text")
        st.success(f"File saved to: {file_path}")


def save_uploaded_file(uploaded_file, directory_path):
      file_name = uploaded_file.name  
      file_path = os.path.join(directory_path, file_name) 
      file_contents = uploaded_file.read()
      
      with open(file_path, "wb") as f:
        f.write(file_contents)
      return file_path, file_contents

def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        signup()  
        login()   
    else:
        file_upload_and_display()  

        

if __name__ == "__main__":
    main()
