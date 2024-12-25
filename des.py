from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import base64
import tkinter as tk
from tkinter import messagebox

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

# Fungsi Enkripsi
def encrypt(plain_text, key):
    des = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plain_text)
    encrypted_text = des.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted_text).decode('utf-8')

# Fungsi Dekripsi
def decrypt(encrypted_text, key):
    des = DES.new(key, DES.MODE_ECB)
    decoded_encrypted_text = base64.b64decode(encrypted_text)
    decrypted_text = des.decrypt(decoded_encrypted_text).decode('utf-8')
    return decrypted_text.rstrip()

# GUI Functions
def perform_encryption():
    plain_text = plain_text_entry.get()
    key_input = key_entry.get()

    if len(key_input) != 8:
        messagebox.showerror("Error", "Key harus memiliki panjang 8 karakter")
        return

    try:
        key = key_input.encode('utf-8')
        encrypted_text = encrypt(plain_text, key)
        encrypted_text_label.config(text=f"Encrypted Text: {encrypted_text}")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal mengenkripsi: {e}")


def perform_decryption():
    encrypted_text = encrypted_text_entry.get()
    key_input = key_entry.get()

    if len(key_input) != 8:
        messagebox.showerror("Error", "Key harus memiliki panjang 8 karakter")
        return

    try:
        key = key_input.encode('utf-8')
        decrypted_text = decrypt(encrypted_text, key)
        decrypted_text_label.config(text=f"Decrypted Text: {decrypted_text}")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal mendekripsi: {e}")

# GUI Setup
root = tk.Tk()
root.title("DES Encryption Tool - GUI Version")
root.geometry("500x400")
root.configure(bg="purple")

# Widgets
frame = tk.Frame(root, padx=10, pady=10, bg="purple")
frame.pack(expand=True)

title_label = tk.Label(frame, text="DES Encryption Tool", font=("Helvetica", 16), bg="purple", fg="white")
title_label.pack(pady=10)

plain_text_label = tk.Label(frame, text="Plain Text:", bg="purple", fg="white")
plain_text_label.pack()
plain_text_entry = tk.Entry(frame, width=40)
plain_text_entry.pack(pady=5)

key_label = tk.Label(frame, text="Key (8 karakter):", bg="purple", fg="white")
key_label.pack()
key_entry = tk.Entry(frame, width=40)
key_entry.pack(pady=5)

encrypted_text_label = tk.Label(frame, text="Encrypted Text: ", bg="purple", fg="white")
encrypted_text_label.pack(pady=5)

encrypted_text_entry = tk.Entry(frame, width=40)
encrypted_text_entry.pack(pady=5)

decrypted_text_label = tk.Label(frame, text="Decrypted Text: ", bg="purple", fg="white")
decrypted_text_label.pack(pady=5)

encrypt_button = tk.Button(frame, text="Encrypt", command=perform_encryption, bg="white", fg="purple")
encrypt_button.pack(pady=5)

decrypt_button = tk.Button(frame, text="Decrypt", command=perform_decryption, bg="white", fg="purple")
decrypt_button.pack(pady=5)

exit_button = tk.Button(frame, text="Keluar", command=root.destroy, bg="white", fg="purple")
exit_button.pack(pady=10)

# Run the GUI
root.mainloop()