import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os
import json
from datetime import datetime

class FileIntegrityChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Checker")
        self.root.geometry("700x500")
        self.root.configure(bg='#f5deb3')  # Light brown background

        self.file_path = tk.StringVar()
        self.hash_algorithm = tk.StringVar(value="SHA256")
        self.stored_hashes = {}
        self.log_file = "integrity_log.json"
        self.load_stored_hashes()

        self.build_gui()

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
        tk.Button(button_frame, text="Compute & Save Hash", command=self.compute_and_store_hash, bg="#deb887").grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Check Integrity", command=self.check_integrity, bg="#deb887").grid(row=0, column=1, padx=10)
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

    def compute_and_store_hash(self):
        path = self.file_path.get()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Invalid file path")
            return

        hash_val = self.compute_hash(path, self.hash_algorithm.get())
        self.stored_hashes[path] = hash_val
        self.save_stored_hashes()
        self.update_status("Hash saved.")
        messagebox.showinfo("Hash Stored", f"Hash saved successfully:\n{hash_val}")

    def check_integrity(self):
        path = self.file_path.get()
        if path not in self.stored_hashes:
            messagebox.showerror("Error", "No stored hash for this file")
            return

        current_hash = self.compute_hash(path, self.hash_algorithm.get())
        stored_hash = self.stored_hashes[path]
        status = "Unchanged" if current_hash == stored_hash else "Modified"

        self.log_check(path, stored_hash, current_hash, status)

        if status == "Unchanged":
            messagebox.showinfo("Integrity Check", "File is intact.")
        else:
            messagebox.showwarning("Integrity Check", "File has been modified!")
        self.update_status(f"Check complete: {status}")

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
