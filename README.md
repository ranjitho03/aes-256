# aes-256


# 🔐 AES-256 File Encryption Tool (GUI Version)

This is a **Python-based graphical tool** that allows you to securely encrypt and decrypt files using **AES-256 (CBC mode)** encryption. It features a simple user interface built with `tkinter`, making it ideal for users who prefer not to work with the command line.

---

## ✅ Features

- Strong **AES-256-CBC encryption**
- Secure **password-based key derivation** using PBKDF2-HMAC-SHA256
- **Graphical user interface** (no terminal required)
- Works on **Windows**, **Mac**, and **Linux**
- Designed to run smoothly in **IDLE** or **by double-clicking**

---

## 🖥️ Screenshot

```
+-------------------------------+
| AES-256 File Encryption Tool |
|                               |
| [ Encrypt a File ]           |
| [ Decrypt a File ]           |
| [ Exit ]                     |
+-------------------------------+
```

---

## 🔧 Requirements

- Python 3.6 or later
- `cryptography` library
- `tkinter` (comes built-in with standard Python)

---

## 📦 Installation

1. **Clone or Download** the project.

2. **Install the required Python library**:

```bash
pip install cryptography
```

3. **Run the tool** using IDLE or by double-clicking:

```bash
python aes_tool_gui.py
```

---

## 🔐 How It Works

- **Encryption:**
  1. Enter a password (used to derive the AES key).
  2. Choose the file you want to encrypt.
  3. Select where to save the encrypted `.enc` file.

- **Decryption:**
  1. Enter the password used for encryption.
  2. Select the `.enc` file.
  3. Choose where to save the decrypted file.

---

## 📁 File Format

The encrypted file contains:
```
[SALT (16 bytes)] + [IV (16 bytes)] + [CIPHERTEXT]
```

This allows secure key derivation and decryption using only the password and encrypted file.

---

## ❗ Notes

- If you enter the wrong password during decryption, you’ll receive an error.
- Make sure to **remember your password** — if lost, your file **cannot be recovered**.
- Large files are supported, but encryption is done in-memory. You can modify for stream encryption if needed.

---

## 📄 License

This tool is provided under the **MIT License** – feel free to modify and use for personal or educational projects.

---

## 👨‍💻 Author
  Ranjith

Ranjith Kumar
