import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

class FileIntegrityChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Checker with Digital Signature")
        self.root.geometry("750x550")
        self.root.configure(bg='#f5deb3')  # Light brown background

        self.file_path = tk.StringVar()
        self.hash_algorithm = tk.StringVar(value="SHA256")
        self.stored_hashes = {}
        self.log_file = "integrity_log.json"
        self.signature_file = "signatures.json"

        self.private_key_file = "private_key.pem"
        self.public_key_file = "public_key.pem"

        self.generate_keys()
        self.load_stored_hashes()

        self.build_gui()

    def generate_keys(self):
        if not os.path.exists(self.private_key_file) or not os.path.exists(self.public_key_file):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            with open(self.private_key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()  # No encryption (no password)
                ))

            public_key = private_key.public_key()
            with open(self.public_key_file, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

    def load_keys(self):
        with open(self.private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,  # No password for private key
                backend=default_backend()
            )
        with open(self.public_key_file, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return private_key, public_key

    def build_gui(self):
        title = tk.Label(self.root, text="File Integrity Checker", font=("Arial", 20, "bold"), bg='#f5deb3')
        title.pack(pady=10)

        file_frame = tk.Frame(self.root, bg='#f5deb3')
        file_frame.pack(pady=10)
        tk.Entry(file_frame, textvariable=self.file_path, width=60).pack(side=tk.LEFT, padx=5)
        tk.Button(file_frame, text="Browse", command=self.browse_file, bg="#d2b48c").pack(side=tk.LEFT)

        algo_frame = tk.Frame(self.root, bg='#f5deb3')
        algo_frame.pack(pady=10)
        tk.Label(algo_frame, text="Select Hash Algorithm:", bg='#f5deb3').pack(side=tk.LEFT, padx=5)
        algo_menu = ttk.Combobox(algo_frame, textvariable=self.hash_algorithm, values=["MD5", "SHA256"], state="readonly")
        algo_menu.pack(side=tk.LEFT)

        button_frame = tk.Frame(self.root, bg='#f5deb3')
        button_frame.pack(pady=20)
        tk.Button(button_frame, text="Compute & Sign Hash", command=self.compute_and_sign_hash, bg="#deb887").grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Check Integrity & Verify Signature", command=self.check_integrity_and_signature, bg="#deb887").grid(row=0, column=1, padx=10)
        tk.Button(button_frame, text="Export Logs", command=self.export_logs, bg="#deb887").grid(row=0, column=2, padx=10)

        self.status = tk.Label(self.root, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg='#f5deb3')
        self.status.pack(fill=tk.X, side=tk.BOTTOM, ipady=4)

    def update_status(self, text):
        self.status.config(text=f"Status: {text}")

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)
            self.update_status("File selected.")

    def compute_hash(self, filepath, algorithm):
        hasher = hashlib.md5() if algorithm == "MD5" else hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()

    def compute_and_sign_hash(self):
        path = self.file_path.get()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Invalid file path")
            return

        hash_val = self.compute_hash(path, self.hash_algorithm.get())
        self.stored_hashes[path] = hash_val
        self.save_stored_hashes()

        private_key, _ = self.load_keys()
        signature = private_key.sign(
            hash_val.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        self.save_signature(path, signature)

        self.update_status("Hash computed and signed.")
        messagebox.showinfo("Success", f"Hash saved and signed.\n{hash_val}")

    def check_integrity_and_signature(self):
        path = self.file_path.get()
        if path not in self.stored_hashes:
            messagebox.showerror("Error", "No stored hash for this file")
            return

        current_hash = self.compute_hash(path, self.hash_algorithm.get())
        stored_hash = self.stored_hashes[path]
        signature = self.load_signature(path)

        _, public_key = self.load_keys()
        try:
            public_key.verify(
                signature,
                stored_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            sig_verified = True
        except Exception:
            sig_verified = False

        status = "Unchanged and Verified" if current_hash == stored_hash and sig_verified else "Modified or Signature Invalid"
        self.log_check(path, stored_hash, current_hash, status)

        if status == "Unchanged and Verified":
            messagebox.showinfo("Integrity Check", "File is intact and signature verified.")
        else:
            messagebox.showwarning("Integrity Check", "File has been modified or signature is invalid!")
        self.update_status(f"Check complete: {status}")

    def save_signature(self, path, signature):
        try:
            if os.path.exists(self.signature_file):
                with open(self.signature_file, "r") as f:
                    data = json.load(f)
            else:
                data = {}
            data[path] = signature.hex()
            with open(self.signature_file, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save signature: {str(e)}")

    def load_signature(self, path):
        try:
            if os.path.exists(self.signature_file):
                with open(self.signature_file, "r") as f:
                    data = json.load(f)
                    return bytes.fromhex(data[path])
        except Exception:
            pass
        return None

    def log_check(self, filepath, stored, current, status):
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file": filepath,
            "stored_hash": stored,
            "current_hash": current,
            "status": status
        }

        logs = []
        if os.path.exists(self.log_file):
            with open(self.log_file, "r") as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []

        logs.append(entry)
        with open(self.log_file, "w") as f:
            json.dump(logs, f, indent=4)

    def export_logs(self):
        if not os.path.exists(self.log_file):
            messagebox.showerror("Error", "No logs to export")
            return

        with open(self.log_file, "r") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Log file is corrupted")
                return

        with open("integrity_logs.csv", "w") as f:
            f.write("Timestamp,File,Stored Hash,Current Hash,Status\n")
            for log in logs:
                f.write(f"{log['timestamp']},{log['file']},{log['stored_hash']},{log['current_hash']},{log['status']}\n")

        self.update_status("Logs exported to integrity_logs.csv")
        messagebox.showinfo("Exported", "Logs have been exported successfully.")

    def save_stored_hashes(self):
        with open("stored_hashes.json", "w") as f:
            json.dump(self.stored_hashes, f, indent=4)

    def load_stored_hashes(self):
        if os.path.exists("stored_hashes.json"):
            with open("stored_hashes.json", "r") as f:
                try:
                    self.stored_hashes = json.load(f)
                except json.JSONDecodeError:
                    self.stored_hashes = {}

if __name__ == '__main__':
    root = tk.Tk()
    app = FileIntegrityChecker(root)
    root.mainloop()
