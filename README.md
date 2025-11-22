# 🔐 CRIPSTEGZ  
### Image Steganography + Crypto Tool (AES-256-CBC)

CRIPSTEGZ is a combined **steganography + cryptography** tool written in Python.  
It hides encrypted data inside PNG images using **LSB Steganography + AES-256-CBC** and also provides **crypto encoding/decoding utilities**.

Released on **PyPI**, installable with:

pipx install cripstegz


---

## 🚀 Features

### 🖼 Steganography
- LSB (Least Significant Bit) Image Steganography  
- AES-256-CBC encrypted payload inside image pixels  
- Supports: **PNG, BMP, TIFF**  
- Auto-converts output to **.png**  
- Hide **text or binary files** inside images  

### 🔑 Crypto Encoding / Decoding
Supports both encode → and decode ←:
- Base64  
- Hex  
- ROT13  
- ROT-N (any shift 1–25)  
- XOR (key-based)  
- Binary ↔ Text  
- URL Encode / Decode  
- Baconian Cipher (A/B pattern)

### 🧩 Hash Utility
- Identifies common hash types:
  - MD5  
  - SHA1  
  - SHA256  
  - SHA512  
  - Generic Base64-like strings  

(No hash cracking.)

---

## 📦 Installation

Install globally from PyPI:

pipx install cripstegz


Run using:

cripstegz


---

## 📚 Usage

### ➤ Start the tool

cripstegz


### ➤ Main Menu

    Steganography

    Crypto

    Hash Identifier

    Exit


### ➤ Encode text into an image
- Choose "Steganography"
- Choose "Encode (Steg)"
- Provide:
  - Cover image  
  - Secret text OR `@file:<path>`  
  - Password  
  - Output name (auto .png)

### ➤ Decode hidden data
- Choose "Decode (Steg)"
- Provide:
  - Stego image  
  - Password  

---

## 📥 Example

Cover image: test.png
Message: Secret data here
Password: asd123
Output: hidden.png

[+] Hidden payload saved as hidden.png


---

## 📌 Requirements

CRIPSTEGZ requires the following Python libraries:

Pillow
pycryptodome


These install automatically when using `pip install cripstegz`.

---

## 📁 Project Structure

cripstegz/
cli.py
init.py
pyproject.toml
README.md


---

## 👨‍💻 Author

**Mohammed Assad**  
Alias: **Ro0tk1e**  
Cybersecurity & Steganography Enthusiast  
GitHub: https://github.com/Ro0tk1e

---

## 🏆 License
MIT License – free for personal & educational use.

---

## ⭐ Support the Project
If you like it, star the GitHub repo 🙌  
More updates & features coming soon.
