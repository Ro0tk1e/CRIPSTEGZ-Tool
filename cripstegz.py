#!/usr/bin/env python3
"""
CRIPSTEGZ - Image LSB Steganography + Crypto Encode/Decode Tool
Single-file tool:
 - Steganography (Image-LSB + AES-256-CBC)
 - Crypto encoders/decoders: Base64, Hex, ROT13, ROT-N, XOR (key), Binary <-> Text, URL, Baconian (A/B)
 - Hash identifier (no cracking)
"""
import sys
import base64
import binascii
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import struct
import urllib.parse

# -----------------------
# Common crypto utilities
# -----------------------
PBKDF2_ITER = 100_000

def pkcs7_pad(b, block=16):
    pad_len = block - (len(b) % block)
    return b + bytes([pad_len]) * pad_len

def pkcs7_unpad(b):
    if not b:
        raise ValueError("Empty plaintext")
    pad = b[-1]
    if pad < 1 or pad > 16:
        raise ValueError("Invalid padding")
    if b[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid padding bytes")
    return b[:-pad]

def derive_key(password, salt, dklen=32):
    if isinstance(password, str):
        password = password.encode('utf-8')
    return PBKDF2(password, salt, dklen, count=PBKDF2_ITER)

# -----------------------
# Steganography functions
# -----------------------
def _to_bits(b: bytes):
    for byte in b:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def _from_bits(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        chunk = bits[i:i+8]
        if len(chunk) < 8:
            break
        for bit in chunk:
            byte = (byte << 1) | (bit & 1)
        out.append(byte)
    return bytes(out)

def _ensure_png_name(name: str) -> str:
    # If no extension -> add .png
    if "." not in name:
        return name + ".png"
    # If jpg/jpeg -> convert to png name
    low = name.lower()
    if low.endswith(".jpg") or low.endswith(".jpeg"):
        base = name.rsplit(".", 1)[0]
        return base + ".png"
    return name

def steg_embed_image(cover_path, message_bytes, password, out_name):
    out_name = _ensure_png_name(out_name)
    # prepare AES payload: salt(16) + iv(16) + len(4) + ct
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pkcs7_pad(message_bytes)
    ct = cipher.encrypt(padded)
    length = struct.pack(">I", len(ct))
    payload = salt + iv + length + ct
    bits = list(_to_bits(payload))

    img = Image.open(cover_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    w, h = img.size
    pixels = list(img.getdata())
    flat = []
    for px in pixels:
        flat.extend(list(px))
    capacity = len(flat)
    if len(bits) > capacity:
        raise ValueError(f"Image capacity insufficient: {capacity} bits available, need {len(bits)}")
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & ~1) | bit
    new_pixels = [tuple(flat[i:i+3]) for i in range(0, len(flat), 3)]
    out_img = Image.new('RGB', (w, h))
    out_img.putdata(new_pixels)
    out_img.save(out_name)
    return out_name

def steg_extract_image(stego_path, password):
    img = Image.open(stego_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    pixels = list(img.getdata())
    flat = []
    for px in pixels:
        flat.extend(list(px))
    # read header (36 bytes -> 36*8 bits)
    header_bits = [(flat[i] & 1) for i in range(36 * 8)]
    header = _from_bits(header_bits)
    if len(header) < 36:
        raise ValueError("Stego header too small or corrupted")
    salt = header[0:16]
    iv = header[16:32]
    length = struct.unpack(">I", header[32:36])[0]
    total_bytes = 36 + length
    total_bits = total_bytes * 8
    if total_bits > len(flat):
        raise ValueError("Stego image does not contain claimed payload (corrupted or wrong file)")
    all_bits = [(flat[i] & 1) for i in range(total_bits)]
    payload = _from_bits(all_bits)
    ct = payload[36:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    pt = pkcs7_unpad(pt_padded)
    return pt  # bytes

# -----------------------
# Crypto encode/decode
# -----------------------
def enc_base64(text: str) -> str:
    return base64.b64encode(text.encode('utf-8')).decode('ascii')

def dec_base64(text: str) -> str:
    try:
        return base64.b64decode(text.encode('ascii')).decode('utf-8')
    except Exception as e:
        raise ValueError("Invalid Base64 input") from e

def enc_hex(text: str) -> str:
    return binascii.hexlify(text.encode('utf-8')).decode('ascii')

def dec_hex(text: str) -> str:
    try:
        return binascii.unhexlify(text.encode('ascii')).decode('utf-8')
    except Exception as e:
        raise ValueError("Invalid hex input") from e

def enc_rot13(text: str) -> str:
    return text.encode('utf-8').decode('rot_13') if hasattr(str, 'decode') else codecs_rot(text, 13)

def dec_rot13(text: str) -> str:
    return codecs_rot(text, 13)

def codecs_rot(s, n):
    # generic rot-n for ASCII letters
    res = []
    for ch in s:
        if 'a' <= ch <= 'z':
            res.append(chr((ord(ch) - ord('a') + n) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            res.append(chr((ord(ch) - ord('A') + n) % 26 + ord('A')))
        else:
            res.append(ch)
    return ''.join(res)

def enc_rotn(text: str, n: int) -> str:
    return codecs_rot(text, n)

def dec_rotn(text: str, n: int) -> str:
    return codecs_rot(text, 26 - (n % 26))

def xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    keylen = len(key)
    for i, b in enumerate(data):
        out.append(b ^ key[i % keylen])
    return bytes(out)

def enc_xor(text: str, key: str) -> str:
    return binascii.hexlify(xor_bytes(text.encode('utf-8'), key.encode('utf-8'))).decode('ascii')

def dec_xor_hex(hextext: str, key: str) -> str:
    try:
        data = binascii.unhexlify(hextext.encode('ascii'))
    except Exception as e:
        raise ValueError("Invalid hex ciphertext for XOR") from e
    return xor_bytes(data, key.encode('utf-8')).decode('utf-8', errors='replace')

def enc_binary(text: str) -> str:
    return ' '.join(format(b, '08b') for b in text.encode('utf-8'))

def dec_binary(text: str) -> str:
    # accept space separated or continuous
    bits = ''.join(ch for ch in text if ch in '01')
    if len(bits) % 8 != 0:
        raise ValueError("Binary length not multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        out.append(int(byte, 2))
    return out.decode('utf-8', errors='replace')

def enc_url(text: str) -> str:
    return urllib.parse.quote(text)

def dec_url(text: str) -> str:
    return urllib.parse.unquote(text)

# Baconian cipher (A/B)
_BACON_DICT = {}
for i, ch in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    # classic Bacon: A=00000 -> represented as A/B where 0->A,1->B
    bits = format(i, '05b')
    pattern = ''.join('B' if bit == '1' else 'A' for bit in bits)
    _BACON_DICT[ch] = pattern
# create reverse map
_BACON_REV = {v: k for k, v in _BACON_DICT.items()}

def enc_bacon(text: str) -> str:
    out = []
    for ch in text.upper():
        if ch >= 'A' and ch <= 'Z':
            out.append(_BACON_DICT[ch])
        elif ch == ' ':
            out.append(' ')  # keep spaces
        else:
            out.append(ch)  # leave digits/punct unchanged
    return ' '.join(out)

def dec_bacon(text: str) -> str:
    # accept only A/B letters; ignore other whitespace; groups of 5 A/B -> letters
    filtered = [c.upper() for c in text if c.upper() in ('A', 'B', ' ')]
    s = ''.join(filtered)
    parts = s.split()
    out = []
    for part in parts:
        if len(part) % 5 != 0:
            raise ValueError("Baconian input length must be multiple of 5 per group")
        for i in range(0, len(part), 5):
            chunk = part[i:i+5]
            if chunk in _BACON_REV:
                out.append(_BACON_REV[chunk])
            else:
                out.append('?')
        out.append(' ')
    return ''.join(out).strip()

# -----------------------
# Hash identifier
# -----------------------
def hash_identifier(s: str) -> str:
    h = s.strip()
    # hex length checks
    hex_chars = all(c in '0123456789abcdefABCDEF' for c in h)
    ln = len(h)
    if hex_chars:
        if ln == 32:
            return "Possible: MD5 (32 hex chars)"
        if ln == 40:
            return "Possible: SHA1 (40 hex chars)"
        if ln == 64:
            return "Possible: SHA256 (64 hex chars)"
        if ln == 128:
            return "Possible: SHA512 (128 hex chars)"
    # base64-ish detection
    try:
        base64.b64decode(h + '===')
        return "Could be Base64 (or other binary data). Not a cryptographic hash (or ambiguous)."
    except Exception:
        pass
    return "Unknown format. Not a recognized hex-length hash."

# -----------------------
# Interactive Menus
# -----------------------
def steg_menu():
    while True:
        print("""
===== STEGANOGRAPHY =====
STEGO SUPPORTED:
  • Image LSB Steganography (PNG, BMP, TIFF)
  • AES-256-CBC encryption inside image pixels
  • JPG not supported (lossy destroys data)

1) Encode (Steg)
2) Decode (Steg)
3) Back
""")
        c = input("Enter choice: ").strip()
        if c == "1":
            # encode steg
            cover = input("Cover image filename: ").strip()
            msg = input("Secret message (or type @file:<path> to embed a file): ").strip()
            password = input("Password: ").strip()
            outname = input("Output filename (any name; .png will be ensured): ").strip()
            # support embedding a file if user types @file:path
            if msg.startswith("@file:"):
                path = msg[len("@file:"):].strip()
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                except Exception as e:
                    print("[-] Failed reading file to embed:", e)
                    continue
            else:
                data = msg.encode('utf-8')
            try:
                saved = steg_embed_image(cover, data, password, outname)
                print(f"[+] Hidden payload saved as: {saved}")
            except Exception as e:
                print("[-] Error embedding:", e)
        elif c == "2":
            # decode steg
            path = input("Stego image filename: ").strip()
            password = input("Password: ").strip()
            try:
                pt = steg_extract_image(path, password)
                # try to decode as utf-8; if fails, show hex and offer save
                try:
                    s = pt.decode('utf-8')
                    print("\n[+] Extracted (interpreted as UTF-8):")
                    print(s)
                except Exception:
                    print("\n[+] Extracted raw bytes (not UTF-8).")
                    save = input("Save bytes to file? (y/N): ").strip().lower()
                    if save == 'y':
                        fn = input("Output filename to save bytes: ").strip()
                        with open(fn, 'wb') as f:
                            f.write(pt)
                        print("[+] Saved to", fn)
                    else:
                        print(binascii.hexlify(pt).decode('ascii'))
            except Exception as e:
                print("[-] Error extracting/decrypting:", e)
        elif c == "3":
            return
        else:
            print("Invalid option.")

def crypto_encode_menu():
    while True:
        print("""
===== ENCODE (CRYPTO) =====
1) Base64
2) Hex
3) ROT13
4) ROT-N (custom shift)
5) XOR (key -> output hex)
6) Binary (text -> bits)
7) URL Encode
8) Baconian (A/B)
9) Back
""")
        c = input("Enter choice: ").strip()
        if c == "1":
            txt = input("Text to encode: ")
            print(enc_base64(txt))
        elif c == "2":
            txt = input("Text to encode: ")
            print(enc_hex(txt))
        elif c == "3":
            txt = input("Text to encode: ")
            print(dec_rot13(txt))  # rot13 is symmetric
        elif c == "4":
            txt = input("Text to encode: ")
            n = input("Shift N (1-25): ").strip()
            try:
                n = int(n) % 26
                print(enc_rotn(txt, n))
            except:
                print("Invalid shift.")
        elif c == "5":
            txt = input("Text to XOR-encode: ")
            key = input("Key (string): ")
            print(enc_xor(txt, key))
        elif c == "6":
            txt = input("Text to binary-encode: ")
            print(enc_binary(txt))
        elif c == "7":
            txt = input("Text to URL-encode: ")
            print(enc_url(txt))
        elif c == "8":
            txt = input("Text to Bacon-encode (letters only): ")
            print(enc_bacon(txt))
        elif c == "9":
            return
        else:
            print("Invalid option.")

def crypto_decode_menu():
    while True:
        print("""
===== DECODE (CRYPTO) =====
1) Base64
2) Hex
3) ROT13
4) ROT-N (custom shift)
5) XOR (hex ciphertext -> key)
6) Binary (bits -> text)
7) URL Decode
8) Baconian (A/B)
9) Back
""")
        c = input("Enter choice: ").strip()
        if c == "1":
            txt = input("Base64 text: ").strip()
            try:
                print(dec_base64(txt))
            except Exception as e:
                print("[-] Error:", e)
        elif c == "2":
            txt = input("Hex text: ").strip()
            try:
                print(dec_hex(txt))
            except Exception as e:
                print("[-] Error:", e)
        elif c == "3":
            txt = input("ROT13 text: ").strip()
            print(dec_rot13(txt))
        elif c == "4":
            txt = input("Text to decode: ").strip()
            n = input("Shift N used to encode (1-25): ").strip()
            try:
                n = int(n) % 26
                print(dec_rotn(txt, n))
            except:
                print("Invalid shift.")
        elif c == "5":
            txt = input("Hex ciphertext (result of XOR encode): ").strip()
            key = input("Key (string): ")
            try:
                print(dec_xor_hex(txt, key))
            except Exception as e:
                print("[-] Error:", e)
        elif c == "6":
            txt = input("Binary (spaces allowed): ").strip()
            try:
                print(dec_binary(txt))
            except Exception as e:
                print("[-] Error:", e)
        elif c == "7":
            txt = input("URL-encoded text: ").strip()
            print(dec_url(txt))
        elif c == "8":
            txt = input("Baconian A/B text: ").strip()
            try:
                print(dec_bacon(txt))
            except Exception as e:
                print("[-] Error:", e)
        elif c == "9":
            return
        else:
            print("Invalid option.")

def hash_menu():
    print("""
===== HASH IDENTIFIER =====
(Only identifies likely hash types; does NOT crack)
""")
    h = input("Enter hash: ").strip()
    print(hash_identifier(h))

# -----------------------
# Main menu
# -----------------------
def main():
    while True:
        print("""
=========== CRIPSTEGZ ===========
Image Steganography + Crypto Tool
------------------------------------

1) Steganography
2) Crypto
3) Hash Identifier
4) Exit
""")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            steg_menu()
        elif choice == "2":
            # crypto -> choose encode or decode
            while True:
                print("""
===== CRYPTO =====
CRYPTO SUPPORTED:
  • Base64
  • Hex
  • ROT13
  • ROT-N (custom shift)
  • XOR (with key)
  • Binary ↔ Text
  • URL Encode/Decode
  • Baconian (Bacon cipher) → works only with A/B pattern

1) Encode (Crypto)
2) Decode (Crypto)
3) Back
""")
                c = input("Enter choice: ").strip()
                if c == "1":
                    crypto_encode_menu()
                elif c == "2":
                    crypto_decode_menu()
                elif c == "3":
                    break
                else:
                    print("Invalid option.")
        elif choice == "3":
            hash_menu()
        elif choice == "4":
            print("Bye.")
            sys.exit(0)
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
