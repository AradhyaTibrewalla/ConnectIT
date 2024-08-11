import os
import shutil
import subprocess
import sys
import webbrowser
from tkinter import *
import bcrypt
from cryptography.fernet import Fernet
from tkinter import messagebox

secured_folder = "secured_folder"
password_file = "encryption.txt"
key_file = 'secret.key'
path_file = 'path.txt'

if not os.path.exists(secured_folder):
    os.makedirs(secured_folder)
    if sys.platform == "win32":
        subprocess.check_call(["attrib", "+H", secured_folder])  

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
            encrypted_path = fernet.encrypt(os.path.abspath(secured_folder).encode())
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
    destination = os.path.join(secured_folder, os.path.basename(file_location))
    shutil.move(file_location, destination)
    encrypt_file(destination, key)
    save_path()
    l6.config(text="File saved and encrypted.")

def open_folder():
    try:
        folder_path = load_path()
        if not folder_path:
            l6.config(text="Failed to retrieve folder path.")
            return
        
        for filename in os.listdir(secured_folder):
            file_path = os.path.join(secured_folder, filename)
            if os.path.isfile(file_path):
                decrypt_file(file_path, key)
        
        abs_path = os.path.abspath(folder_path)
        if sys.platform == "win32":
            os.startfile(abs_path)
        elif sys.platform == "darwin":
            subprocess.run(["open", abs_path])
        elif sys.platform == "linux":
            subprocess.run(["xdg-open", abs_path])
        else:
            l6.config(text="Unsupported operating system.")
            return

        l6.config(text="Folder opened successfully.")

    except Exception as e:
        l6.config(text=f"Failed to open folder: {str(e)}")

def call_it_engineer():
    try:
        phone_number = "1234567890"  
        whatsapp_url = f"https://wa.me/{phone_number}"

        webbrowser.open(whatsapp_url)
        l6.config(text="WhatsApp chat opened. Please start the call manually.")
    except Exception as e:
        l6.config(text=f"Failed to initiate WhatsApp call: {str(e)}")

root = Tk()
primary_color = "#34495e"
secondary_color = "#2ecc71"
font_color = "#ecf0f1"

root.title("ConnectIT ----> Hackathon Project.")
root.geometry("600x450")
root.config(bg=primary_color)

def setup_password_ui():
    global e1, l1, l2, l3, b1
    l1 = Label(root, text="ConnectIT", font=("Times New Roman", 24, "bold"), bg=primary_color, fg=font_color)
    e1 = Entry(root, font=("Times New Roman", 15), show="*", bg=secondary_color, fg=font_color)
    b1 = Button(root, text="Next", font=("Times New Roman", 12, "bold"), padx=30, bg=secondary_color, fg=primary_color, command=handle_password)
    
    if os.path.exists(password_file):
        l3 = Label(root, text="Enter the Passcode: ", font=("Times New Roman", 16), bg=primary_color, fg=font_color)
    else:
        l3 = Label(root, text="Set the Passcode: ", font=("Times New Roman", 16), bg=primary_color, fg=font_color)
    
    l2 = Label(root, text="", bg=primary_color, fg=font_color, font=("Times New Roman", 12))
    
    l1.place(x=200, y=30)
    e1.place(x=150, y=120)
    l3.place(x=150, y=90)
    l2.place(x=150, y=160)
    b1.place(x=250, y=200)

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
        l3.config(text="Enter the Passcode: ")

def save_file():
    file_location = e2.get()
    file_location = os.path.normpath(file_location)
    if os.path.isfile(file_location):
        encrypt_and_save_file(file_location)
    else:
        l6.config(text="File not found. Check the path and try again.")

def show_file_input_and_options():
    global l4, e2, b_save, b_quit, l6, l_open_folder, b_open_folder, b_call_support, b_quit_final
    l1.destroy()
    e1.destroy()
    b1.destroy()
    l2.destroy()
    l3.destroy()

    frame_file_input = Frame(root, bg=primary_color)
    frame_file_input.place(x=50, y=50, width=500, height=150)

    l4 = Label(frame_file_input, text="Enter File Location:", font=("Times New Roman", 16), bg=primary_color, fg=font_color)
    e2 = Entry(frame_file_input, font=("Times New Roman", 12), width=40, bg=secondary_color, fg=font_color)
    l4.pack(pady=10)
    e2.pack(pady=5)

    b_save = Button(frame_file_input, text="Save File", font=("Times New Roman", 15, "bold"), bg=secondary_color, fg=primary_color, command=save_file)
    b_save.pack(pady=10)

    frame_folder_management = Frame(root, bg=primary_color)
    frame_folder_management.place(x=50, y=230, width=500, height=150)

    l6 = Label(frame_folder_management, text="", font=("Times New Roman", 15), bg=primary_color, fg=font_color)
    l6.pack(pady=10)

    l_open_folder = Label(frame_folder_management, text="Do you want to open the folder?", font=("Times New Roman", 15), bg=primary_color, fg=font_color)
    l_open_folder.pack(pady=10)

    b_open_folder = Button(frame_folder_management, text="Open Folder", font=("Times New Roman", 15, "bold"), bg=secondary_color, fg=primary_color, command=open_folder)
    b_open_folder.pack(side=LEFT, padx=10)

    b_call_support = Button(frame_folder_management, text="Call IT Engineer", font=("Times New Roman", 15, "bold"), bg=secondary_color, fg=primary_color, command=call_it_engineer)
    b_call_support.pack(side=LEFT, padx=10)

    b_quit_final = Button(frame_folder_management, text="Quit", font=("Times New Roman", 15, "bold"), bg=secondary_color, fg=primary_color, command=root.quit)
    b_quit_final.pack(side=RIGHT, padx=10)

setup_password_ui()
root.mainloop()
