import os
import shutil
import subprocess
import sys
from tkinter import *
import bcrypt
from cryptography.fernet import Fernet

# Folder and file paths
secured_folder = "secured_folder"
hidden_folder = os.path.join(secured_folder, ".hidden_folder")
password_file = "encryption.txt"
key_file = 'secret.key'
path_file = 'path.txt'

# Ensure the secured folder and hidden folder exist
if not os.path.exists(secured_folder):
    os.makedirs(secured_folder)
if not os.path.exists(hidden_folder):
    os.makedirs(hidden_folder)

def generate_key():
    key = Fernet.generate_key()
    with open(key_file, 'wb') as key_file:
        key_file.write(key)
    return key

def load_key():
    return open(key_file, 'rb').read()

key = generate_key() if not os.path.exists(key_file) else load_key()

def encrypt_file(file_name, key):
    fernet = Fernet(key)
    with open(file_name, 'rb') as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(file_name, 'wb') as f:
        f.write(encrypted)

def decrypt_file(file_name, key):
    fernet = Fernet(key)
    with open(file_name, 'rb') as f:
        encrypted_data = f.read()
    decrypted = fernet.decrypt(encrypted_data)
    with open(file_name, 'wb') as f:
        f.write(decrypted)

def save_path():
    try:
        with open(path_file, 'wb') as file:
            fernet = Fernet(key)
            encrypted_path = fernet.encrypt(os.path.abspath(hidden_folder).encode())
            file.write(encrypted_path)
    except Exception as e:
        l6.config(text=f"Failed to save path: {str(e)}")

def load_path():
    try:
        with open(path_file, 'rb') as file:
            fernet = Fernet(key)
            encrypted_path = file.read()
            decrypted_path = fernet.decrypt(encrypted_path).decode()
            return decrypted_path
    except Exception as e:
        l6.config(text=f"Failed to load path: {str(e)}")
        return None

def encrypt_and_save_file(file_location):
    destination = os.path.join(hidden_folder, os.path.basename(file_location))
    shutil.move(file_location, destination)
    encrypt_file(destination, key)
    save_path()
    l6.config(text="File saved and encrypted in the hidden folder.")

def open_folder():
    try:
        folder_path = load_path()
        if not folder_path:
            l6.config(text="Failed to retrieve folder path.")
            return
        
        # Open the hidden folder
        abs_path = os.path.abspath(folder_path)
        if sys.platform == "win32":
            subprocess.Popen(f'explorer "{abs_path}"')
        elif sys.platform == "darwin":
            subprocess.run(["open", abs_path])
        elif sys.platform == "linux":
            subprocess.run(["xdg-open", abs_path])
        else:
            l6.config(text="Unsupported operating system.")
            return

        l6.config(text="Hidden folder opened successfully.")

    except Exception as e:
        l6.config(text=f"Failed to open folder: {str(e)}")

# Tkinter window setup with improved design
root = Tk()
grey = "#343a40"
accent_color = "#ffc107"
text_color = "#ffffff"
root.title("ConnectIT ----> Hackathon Project")
root.geometry("600x500")
root.config(bg=grey)

def setup_password_ui():
    global e1, l1, l2, l3, b1
    l1 = Label(root, text="ConnectIT", font=("Arial", 24, "bold"), fg=accent_color, bg=grey)
    e1 = Entry(root, font=("Arial", 16, "bold"), show="*", bg="#495057", fg=text_color, insertbackground=text_color)
    b1 = Button(root, text="Next", font=("Arial", 14, "bold"), bg=accent_color, fg=grey, padx=30, command=handle_password)
    
    if os.path.exists(password_file):
        l3 = Label(root, text="Enter the Passcode:", font=("Arial", 16), fg=text_color, bg=grey)
    else:
        l3 = Label(root, text="Set the Passcode:", font=("Arial", 16), fg=text_color, bg=grey)
    
    l2 = Label(root, text="", bg=grey, fg=accent_color, font=("Arial", 12))
    
    l1.pack(pady=30)
    l3.pack(pady=10)
    e1.pack(pady=10)
    b1.pack(pady=20)
    l2.pack()

def handle_password():
    if os.path.exists(password_file):
        input_password = e1.get()
        with open(password_file, "rb") as file:
            stored_hashed_password = file.read()
        if bcrypt.checkpw(input_password.encode(), stored_hashed_password):
            l2.config(text="Access Granted.")
            show_file_input_and_options()
        else:
            l2.config(text="Access Denied.")
    else:
        new_password = e1.get()
        hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        with open(password_file, "wb") as file:
            file.write(hashed_password)
        l2.config(text="Passcode is set. Enter the passcode again.")
        l3.config(text="Enter the Passcode:")

def save_file():
    file_location = e2.get()
    file_location = os.path.normpath(file_location)  # Normalize the path
    if os.path.isfile(file_location):
        encrypt_and_save_file(file_location)
    else:
        l6.config(text="File not found. Check the path and try again.")

def show_file_input_and_options():
    global l4, e2, b_save, b_quit, l6, l_open_folder, b_open_folder, b_quit_final
    for widget in root.winfo_children():
        widget.destroy()

    # Frame for file input
    frame_file_input = Frame(root, bg=grey)
    frame_file_input.place(x=50, y=50, width=500, height=150)

    # File location label and entry
    l4 = Label(frame_file_input, text="Enter File Location:", font=("Arial", 16), fg=text_color, bg=grey)
    e2 = Entry(frame_file_input, font=("Arial", 14), width=40, bg="#495057", fg=text_color, insertbackground=text_color)
    b_save = Button(frame_file_input, text="Save File", font=("Arial", 14, "bold"), bg=accent_color, fg=grey, command=save_file)

    l4.pack(pady=10)
    e2.pack(pady=10)
    b_save.pack(pady=10)

    # Frame for folder management
    frame_folder_management = Frame(root, bg=grey)
    frame_folder_management.place(x=50, y=250, width=500, height=200)

    # Folder management label and buttons
    l6 = Label(frame_folder_management, text="", font=("Arial", 14), fg=text_color, bg=grey)
    l_open_folder = Label(frame_folder_management, text="Do you want to open the folder?", font=("Arial", 16), fg=text_color, bg=grey)
    b_open_folder = Button(frame_folder_management, text="Open Folder", font=("Arial", 14, "bold"), bg=accent_color, fg=grey, command=open_folder)
    b_quit_final = Button(frame_folder_management, text="Quit", font=("Arial", 14, "bold"), bg="#dc3545", fg=text_color, command=root.quit)

    l_open_folder.pack(pady=10)
    b_open_folder.pack(side=LEFT, padx=30)
    b_quit_final.pack(side=RIGHT, padx=30)
    l6.pack(pady=20)

setup_password_ui()
root.mainloop()
