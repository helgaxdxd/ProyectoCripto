import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import ecdsa
from hashlib import sha256
import base64

class SignatureApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Digital Signature with ECDSA and Encryption with AES")
        self.geometry("600x700")

        # Create widgets
        self.create_widgets()

    def create_widgets(self):
        # Create frames
        sign_frame = tk.LabelFrame(self, text="Sign a File", padx=10, pady=10)
        sign_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        verify_frame = tk.LabelFrame(self, text="Verify a Signed File", padx=10, pady=10)
        verify_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        encrypt_frame = tk.LabelFrame(self, text="Encrypt a File", padx=10, pady=10)
        encrypt_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        decrypt_frame = tk.LabelFrame(self, text="Decrypt a File", padx=10, pady=10)
        decrypt_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        # Signing section
        self.sign_file_entry = tk.Entry(sign_frame, width=50)
        self.sign_file_entry.grid(row=0, column=0, padx=5, pady=5)

        self.sign_file_button = tk.Button(sign_frame, text="Browse File", command=self.browse_sign_file)
        self.sign_file_button.grid(row=0, column=1, padx=5, pady=5)

        self.private_key_entry = tk.Entry(sign_frame, width=50, show="*")
        self.private_key_entry.grid(row=1, column=0, padx=5, pady=5)

        self.private_key_button = tk.Button(sign_frame, text="Browse Private Key", command=self.browse_private_key)
        self.private_key_button.grid(row=1, column=1, padx=5, pady=5)

        self.sign_button = tk.Button(sign_frame, text="Sign File", command=self.sign_file)
        self.sign_button.grid(row=2, column=0, columnspan=2, pady=5)

        # Verification section
        self.verify_file_entry = tk.Entry(verify_frame, width=50)
        self.verify_file_entry.grid(row=0, column=0, padx=5, pady=5)

        self.verify_file_button = tk.Button(verify_frame, text="Browse File", command=self.browse_verify_file)
        self.verify_file_button.grid(row=0, column=1, padx=5, pady=5)

        self.public_key_entry = tk.Entry(verify_frame, width=50, show="*")
        self.public_key_entry.grid(row=1, column=0, padx=5, pady=5)

        self.public_key_button = tk.Button(verify_frame, text="Browse Public Key", command=self.browse_public_key)
        self.public_key_button.grid(row=1, column=1, padx=5, pady=5)

        self.verify_button = tk.Button(verify_frame, text="Verify File", command=self.verify_signature)
        self.verify_button.grid(row=2, column=0, columnspan=2, pady=5)

        # Encryption section
        self.encrypt_file_entry = tk.Entry(encrypt_frame, width=50)
        self.encrypt_file_entry.grid(row=0, column=0, padx=5, pady=5)

        self.encrypt_file_button = tk.Button(encrypt_frame, text="Browse File", command=self.browse_encrypt_file)
        self.encrypt_file_button.grid(row=0, column=1, padx=5, pady=5)

        self.dh_secret_entry = tk.Entry(encrypt_frame, width=50, show="*")
        self.dh_secret_entry.grid(row=1, column=0, padx=5, pady=5)

        self.dh_secret_button = tk.Button(encrypt_frame, text="Browse DH Secret", command=self.browse_dh_secret)
        self.dh_secret_button.grid(row=1, column=1, padx=5, pady=5)

        self.encrypt_button = tk.Button(encrypt_frame, text="Encrypt File", command=self.encrypt_file_dh)
        self.encrypt_button.grid(row=2, column=0, columnspan=2, pady=5)

        # Decryption section
        self.decrypt_file_entry = tk.Entry(decrypt_frame, width=50)
        self.decrypt_file_entry.grid(row=0, column=0, padx=5, pady=5)

        self.decrypt_file_button = tk.Button(decrypt_frame, text="Browse File", command=self.browse_decrypt_file)
        self.decrypt_file_button.grid(row=0, column=1, padx=5, pady=5)

        self.dh_private_key_entry = tk.Entry(decrypt_frame, width=50, show="*")
        self.dh_private_key_entry.grid(row=1, column=0, padx=5, pady=5)

        self.dh_private_key_button = tk.Button(decrypt_frame, text="Browse DH Private Key", command=self.browse_dh_private_key)
        self.dh_private_key_button.grid(row=1, column=1, padx=5, pady=5)

        self.decrypt_button = tk.Button(decrypt_frame, text="Decrypt File", command=self.decrypt_file_dh)
        self.decrypt_button.grid(row=2, column=0, columnspan=2, pady=5)

    def browse_sign_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        self.sign_file_entry.delete(0, tk.END)
        self.sign_file_entry.insert(0, file_path)

    def browse_verify_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        self.verify_file_entry.delete(0, tk.END)
        self.verify_file_entry.insert(0, file_path)

    def browse_private_key(self):
        key_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        self.private_key_entry.delete(0, tk.END)
        self.private_key_entry.insert(0, key_path)

    def browse_public_key(self):
        key_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        self.public_key_entry.delete(0, tk.END)
        self.public_key_entry.insert(0, key_path)

    def browse_encrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        self.encrypt_file_entry.delete(0, tk.END)
        self.encrypt_file_entry.insert(0, file_path)

    def browse_decrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        self.decrypt_file_entry.delete(0, tk.END)
        self.decrypt_file_entry.insert(0, file_path)

    def browse_dh_secret(self):
        dh_secret_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        self.dh_secret_entry.delete(0, tk.END)
        self.dh_secret_entry.insert(0, dh_secret_path)

    def browse_dh_private_key(self):
        dh_private_key_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        self.dh_private_key_entry.delete(0, tk.END)
        self.dh_private_key_entry.insert(0, dh_private_key_path)

    def sign_file(self):
        file_path = self.sign_file_entry.get()
        private_key_path = self.private_key_entry.get()
        try:
            with open(private_key_path, "rb") as f:
                sk = ecdsa.SigningKey.from_pem(f.read())

            with open(file_path, "rb") as f:
                message = f.read()

            signature = sk.sign(message, hashfunc=sha256)
            with open(file_path, "ab") as f:
                f.write(b"\n---SIGNATURE---\n")
                f.write(signature)

            messagebox.showinfo("Success", "File signed and signature appended.")
        except Exception as e:
            messagebox.showerror("Error", "Failed to sign file: " + str(e))

    def verify_signature(self):
        file_path = self.verify_file_entry.get()
        public_key_path = self.public_key_entry.get()
        try:
            with open(public_key_path, "rb") as f:
                vk = ecdsa.VerifyingKey.from_pem(f.read())

            with open(file_path, "rb") as f:
                content = f.read()

            message, signature = content.rsplit(b"\n---SIGNATURE---\n", 1)

            if vk.verify(signature, message, hashfunc=sha256):
                messagebox.showinfo("Success", "Verification successful: The signature is valid.")
            else:
                messagebox.showerror("Error", "Verification failed: The signature is not valid.")
        except Exception as e:
                       messagebox.showerror("Error", "Failed to verify signature: " + str(e))

    def encrypt_file_dh(self):
        file_path = self.encrypt_file_entry.get()
        dh_secret_path = self.dh_secret_entry.get()
        try:
            with open(file_path, "rb") as f:
                plaintext = f.read()

            with open(dh_secret_path, "rb") as f:
                dh_secret = f.read()

            # Generate AES key and IV
            aes_key = sha256(dh_secret).digest()[:16]  # Use the first 16 bytes of DH secret as AES key
            iv = get_random_bytes(16)  # 128-bit IV

            # Encrypt the plaintext with AES
            aes_cipher = AES.new(aes_key, AES.MODE_CFB, iv)
            ciphertext = aes_cipher.encrypt(plaintext)

            # Save the AES key and IV to the file
            with open(file_path, "wb") as f:
                f.write(base64.b64encode(iv) + b"\n")
                f.write(base64.b64encode(ciphertext))

            messagebox.showinfo("Success", "File encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", "Failed to encrypt file: " + str(e))

    def decrypt_file_dh(self):
        file_path = self.decrypt_file_entry.get()
        dh_private_key_path = self.dh_private_key_entry.get()
        try:
            with open(file_path, "rb") as f:
                iv = base64.b64decode(f.readline().strip())
                ciphertext = base64.b64decode(f.read())

            with open(dh_private_key_path, "rb") as f:
                dh_private_key = f.read()

            # Generate AES key from DH private key
            aes_key = sha256(dh_private_key).digest()[:16]  # Use the first 16 bytes of DH private key as AES key

            # Decrypt the ciphertext with AES
            aes_cipher = AES.new(aes_key, AES.MODE_CFB, iv)
            plaintext = aes_cipher.decrypt(ciphertext)

            # Save the decrypted plaintext to a new file
            decrypted_file_path = file_path + ".decrypted"
            with open(decrypted_file_path, "wb") as f:
                f.write(plaintext)

            messagebox.showinfo("Success", f"File decrypted successfully. Saved as {decrypted_file_path}.")
        except Exception as e:
            messagebox.showerror("Error", "Failed to decrypt file: " + str(e))

if __name__ == "__main__":
    app = SignatureApp()
    app.mainloop()
