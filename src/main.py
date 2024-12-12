import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

class RSACryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption System")

        # Key pair variables
        self.private_key = None
        self.public_key = None

        # Language settings
        self.languages = {
            "en": {
                "generate_keys": "Generate Keys",
                "message_to_encrypt": "Message to Encrypt:",
                "encrypt": "Encrypt",
                "encrypted_message": "Encrypted Message:",
                "decrypt": "Decrypt",
                "decrypted_message": "Decrypted Message:",
                "keys_generated": "Keys Generated",
                "keys_message": "Public and Private keys have been generated.",
                "error": "Error",
                "enter_message": "Please enter a message to encrypt.",
                "keys_not_generated": "Keys have not been generated yet.",
                "enter_encrypted_message": "Please enter an encrypted message to decrypt.",
                "decryption_failed": "Decryption failed: ",
                "load_file": "Load File",
                "save_file": "Save File"
            },
            "uk": {
                "generate_keys": "Генерувати ключі",
                "message_to_encrypt": "Повідомлення для шифрування:",
                "encrypt": "Зашифрувати",
                "encrypted_message": "Зашифроване повідомлення:",
                "decrypt": "Розшифрувати",
                "decrypted_message": "Розшифроване повідомлення:",
                "keys_generated": "Ключі згенеровано",
                "keys_message": "Публічний і приватний ключі згенеровано.",
                "error": "Помилка",
                "enter_message": "Будь ласка, введіть повідомлення для шифрування.",
                "keys_not_generated": "Ключі ще не згенеровано.",
                "enter_encrypted_message": "Будь ласка, введіть зашифроване повідомлення для розшифрування.",
                "decryption_failed": "Помилка розшифрування: ",
                "load_file": "Завантажити файл",
                "save_file": "Зберегти файл"
            }
        }
        self.current_language = "en"

        # UI Elements
        self.setup_ui()

    def setup_ui(self):
        # Language selection
        self.language_var = tk.StringVar(value=self.current_language)
        self.language_menu = tk.OptionMenu(
            self.root, self.language_var, *self.languages.keys(), command=self.change_language
        )
        self.language_menu.pack(pady=10)

        # Generate keys button
        self.generate_keys_btn = tk.Button(self.root, text=self.get_text("generate_keys"), command=self.generate_keys)
        self.generate_keys_btn.pack(pady=10)

        # File Encryption/Decryption Section
        self.file_frame = tk.Frame(self.root)
        self.file_frame.pack(pady=10)

        self.load_file_btn = tk.Button(self.file_frame, text=self.get_text("load_file"), command=self.load_file)
        self.load_file_btn.grid(row=0, column=0, padx=5)

        self.save_file_btn = tk.Button(self.file_frame, text=self.get_text("save_file"), command=self.save_file)
        self.save_file_btn.grid(row=0, column=1, padx=5)

        # Encrypt Section
        self.encrypt_label = tk.Label(self.root, text=self.get_text("message_to_encrypt"))
        self.encrypt_label.pack()
        self.encrypt_entry = tk.Entry(self.root, width=50)
        self.encrypt_entry.pack(pady=5)
        self.encrypt_btn = tk.Button(self.root, text=self.get_text("encrypt"), command=self.encrypt_message)
        self.encrypt_btn.pack(pady=10)

        # Decrypt Section
        self.decrypt_label = tk.Label(self.root, text=self.get_text("encrypted_message"))
        self.decrypt_label.pack()
        self.decrypt_entry = tk.Entry(self.root, width=50)
        self.decrypt_entry.pack(pady=5)
        self.decrypt_btn = tk.Button(self.root, text=self.get_text("decrypt"), command=self.decrypt_message)
        self.decrypt_btn.pack(pady=10)

        # Output Section
        self.output_label = tk.Label(self.root, text="Output:")
        self.output_label.pack()
        self.output_text = tk.Text(self.root, height=10, width=60, state=tk.DISABLED)
        self.output_text.pack(pady=10)

    def get_text(self, key):
        return self.languages[self.current_language].get(key, key)

    def change_language(self, lang):
        self.current_language = lang
        self.update_ui_texts()

    def update_ui_texts(self):
        self.generate_keys_btn.config(text=self.get_text("generate_keys"))
        self.load_file_btn.config(text=self.get_text("load_file"))
        self.save_file_btn.config(text=self.get_text("save_file"))
        self.encrypt_label.config(text=self.get_text("message_to_encrypt"))
        self.encrypt_btn.config(text=self.get_text("encrypt"))
        self.decrypt_label.config(text=self.get_text("encrypted_message"))
        self.decrypt_btn.config(text=self.get_text("decrypt"))

    def generate_keys(self):
        """Generate RSA key pair."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        messagebox.showinfo(self.get_text("keys_generated"), self.get_text("keys_message"))

    def load_file(self):
        """Load a file for encryption or decryption."""
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, "rb") as file:
                data = file.read()
                self.encrypt_entry.delete(0, tk.END)
                self.encrypt_entry.insert(0, data.decode(errors="ignore"))

    def save_file(self):
        """Save the encrypted or decrypted content to a file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, "wb") as file:
                data = self.output_text.get(1.0, tk.END).strip()
                # Remove labels like "Encrypted Message:" or "Decrypted Message:" before saving
                if "\n" in data:
                    content = data.split("\n", 1)[1]
                else:
                    content = data
                file.write(content.encode())

    def encrypt_message(self):
        """Encrypt the provided message using the public key."""
        message = self.encrypt_entry.get()
        if not message:
            messagebox.showerror(self.get_text("error"), self.get_text("enter_message"))
            return
        if not self.public_key:
            messagebox.showerror(self.get_text("error"), self.get_text("keys_not_generated"))
            return

        encrypted_message = self.public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.decrypt_entry.delete(0, tk.END)
        self.decrypt_entry.insert(0, encrypted_message.hex())
        self.display_output(self.get_text("encrypted_message"), encrypted_message.hex())

    def decrypt_message(self):
        """Decrypt the provided encrypted message using the private key."""
        encrypted_message_hex = self.decrypt_entry.get()
        if not encrypted_message_hex:
            messagebox.showerror(self.get_text("error"), self.get_text("enter_encrypted_message"))
            return
        if not self.private_key:
            messagebox.showerror(self.get_text("error"), self.get_text("keys_not_generated"))
            return

        try:
            encrypted_message = bytes.fromhex(encrypted_message_hex)
            decrypted_message = self.private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.display_output(self.get_text("decrypted_message"), decrypted_message.decode())
        except Exception as e:
            messagebox.showerror(self.get_text("error"), f"{self.get_text('decryption_failed')}{e}")

    def display_output(self, title, content):
        """Display output in the text widget."""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"{title}\n{content}\n")
        self.output_text.config(state=tk.DISABLED)

# Main application loop
if __name__ == "__main__":
    root = tk.Tk()
    app = RSACryptoApp(root)
    root.mainloop()