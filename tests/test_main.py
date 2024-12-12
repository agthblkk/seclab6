import unittest
from unittest.mock import Mock, patch
from tkinter import Tk
import sys
import os
from dotenv import load_dotenv
load_dotenv()
sys.path.insert(0, 'C:/Users/Test/PycharmProjects/seclab6/src')
from main import RSACryptoApp



class TestRSACryptoApp(unittest.TestCase):

    def setUp(self):
        self.root = Tk()
        self.app = RSACryptoApp(self.root)

    def tearDown(self):
        self.root.destroy()

    def test_generate_keys(self):
        self.app.generate_keys()
        self.assertIsNotNone(self.app.private_key, "Private key should not be None after generation.")
        self.assertIsNotNone(self.app.public_key, "Public key should not be None after generation.")

    def test_encrypt_message(self):
        self.app.generate_keys()
        test_message = "Hello, RSA!"
        self.app.encrypt_entry.insert(0, test_message)

        self.app.encrypt_message()

        encrypted_message = self.app.decrypt_entry.get()
        self.assertNotEqual(encrypted_message, "", "Encrypted message should not be empty.")
        self.assertNotEqual(encrypted_message, test_message, "Encrypted message should not match the original message.")

    def test_decrypt_message(self):
        self.app.generate_keys()
        test_message = "Hello, RSA!"

        # Simulate encryption
        self.app.encrypt_entry.insert(0, test_message)
        self.app.encrypt_message()
        encrypted_message = self.app.decrypt_entry.get()

        # Simulate decryption
        self.app.decrypt_entry.delete(0, "end")
        self.app.decrypt_entry.insert(0, encrypted_message)
        self.app.decrypt_message()

        decrypted_message = self.app.output_text.get("1.0", "end").strip()
        self.assertIn(test_message, decrypted_message, "Decrypted message should match the original message.")

    @patch("builtins.open", new_callable=unittest.mock.mock_open, read_data="Sample data")
    def test_load_file(self, mock_open):
        self.app.load_file()
        mock_open.assert_called_once()
        self.assertEqual(self.app.encrypt_entry.get(), "Sample data", "Loaded data should match file content.")

    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    def test_save_file(self, mock_open):
        self.app.generate_keys()
        test_message = "Hello, RSA!"

        # Simulate encryption
        self.app.encrypt_entry.insert(0, test_message)
        self.app.encrypt_message()

        self.app.save_file()
        mock_open.assert_called_once()
        handle = mock_open()
        written_content = handle.write.call_args[0][0]
        self.assertIn("Encrypted", written_content, "Saved file should contain encrypted content.")

if __name__ == "__main__":
    unittest.main()
