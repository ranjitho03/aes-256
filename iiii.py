import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

# Constants
KEY_LENGTH = 32
IV_LENGTH = 16
SALT_LENGTH = 16
ITERATIONS = 100_000
backend = default_backend()

# File Picker Functions
def select_file(title):
    root = tk.Tk()
    root.withdraw()
    root.update()
    file_path = filedialog.askopenfilename(title=title)
    root.destroy()
    return file_path

def save_file(title, default_ext):
    root = tk.Tk()
    root.withdraw()
    root.update()
    file_path = filedialog.asksaveasfilename(title=title, defaultextension=default_ext)
    root.destroy()
    return file_path

def ask_password(prompt):
    root = tk.Tk()
    root.withdraw()
    password = simpledialog.askstring("Password", prompt, show='*')
    root.destroy()
    return password

# Key derivation
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=backend
    )
    return kdf.derive(password.encode())

# Encryption
def encrypt_file():
    password = ask_password("Enter encryption password:")
    if not password:
        return

    input_path = select_file("Select file to encrypt")
    if not input_path:
        return

    output_path = save_file("Save encrypted file as", ".enc")
    if not output_path:
        return

    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)
    key = derive_key(password, salt)

    with open(input_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    messagebox.showinfo("Success", f"File encrypted and saved to:\n{output_path}")

# Decryption
def decrypt_file():
    password = ask_password("Enter decryption password:")
    if not password:
        return

    input_path = select_file("Select encrypted file to decrypt")
    if not input_path:
        return

    output_path = save_file("Save decrypted file as", "")
    if not output_path:
        return

    with open(input_path, 'rb') as f:
        file_data = f.read()

    salt = file_data[:SALT_LENGTH]
    iv = file_data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
    ciphertext = file_data[SALT_LENGTH + IV_LENGTH:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        data = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        messagebox.showerror("Error", "Incorrect password or corrupted file.")
        return

    with open(output_path, 'wb') as f:
        f.write(data)

    messagebox.showinfo("Success", f"File decrypted and saved to:\n{output_path}")

# GUI Menu
def main_menu():
    root = tk.Tk()
    root.title("AES-256 File Encryption Tool")
    root.geometry("300x200")

    tk.Label(root, text="AES-256 File Encryption Tool", font=("Arial", 14, "bold")).pack(pady=10)

    tk.Button(root, text="Encrypt a File", width=20, command=encrypt_file).pack(pady=10)
    tk.Button(root, text="Decrypt a File", width=20, command=decrypt_file).pack(pady=10)
    tk.Button(root, text="Exit", width=20, command=root.destroy).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main_menu()

