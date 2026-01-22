import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import binascii

# Known file signatures (Magic Numbers)
FILE_SIGNATURES = {
    "JPEG": "FFD8FF",
    "PNG": "89504E47",
    "GIF": "47494638",
    "PDF": "25504446",
    "ZIP": "504B0304",
    "EXE": "4D5A",
    "MP3": "494433",
    "MP4": "00000018FTYPMP4"
}

class FileTypeIdentifier:
    def __init__(self, root):
        self.root = root
        self.root.title("File Type Identifier")
        self.root.geometry("600x400")
        
        self.file_path = tk.StringVar()
        self.result_text = tk.StringVar()
        
        tk.Label(root, text="Select a File:").pack(pady=5)
        tk.Entry(root, textvariable=self.file_path, width=50).pack(pady=5)
        tk.Button(root, text="Browse", command=self.browse_file).pack(pady=5)
        tk.Button(root, text="Identify File Type", command=self.identify_file_type).pack(pady=10)
        
        tk.Label(root, text="Results:").pack(pady=5)
        self.result_display = tk.Text(root, height=10, width=70, wrap=tk.WORD)
        self.result_display.pack(pady=5)
        
        tk.Button(root, text="Batch Identify Files", command=self.batch_identify).pack(pady=10)
        
    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
    
    def get_file_signature(self, file_path, num_bytes=8):
        """Read the first few bytes of a file to determine its signature."""
        try:
            with open(file_path, "rb") as file:
                file_signature = binascii.hexlify(file.read(num_bytes)).decode().upper()
                return file_signature
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file: {str(e)}")
            return None
    
    def identify_file_type(self):
        file_path = self.file_path.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Invalid file path")
            return
        
        file_signature = self.get_file_signature(file_path)
        if not file_signature:
            return
        
        detected_type = "Unknown"
        for file_type, signature in FILE_SIGNATURES.items():
            if file_signature.startswith(signature):
                detected_type = file_type
                break
        
        file_extension = os.path.splitext(file_path)[1].lower()
        result = f"File: {file_path}\nDetected Type: {detected_type}\nFile Extension: {file_extension}\nSignature: {file_signature}"
        
        self.result_display.delete(1.0, tk.END)
        self.result_display.insert(tk.END, result)
        messagebox.showinfo("File Type Identified", result)
        
    def batch_identify(self):
        directory = filedialog.askdirectory()
        if not directory:
            return
        
        results = "Batch File Identification Results:\n"
        
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_signature = self.get_file_signature(file_path)
                detected_type = "Unknown"
                for file_type, signature in FILE_SIGNATURES.items():
                    if file_signature and file_signature.startswith(signature):
                        detected_type = file_type
                        break
                
                file_extension = os.path.splitext(file)[1].lower()
                results += f"File: {file}\nDetected Type: {detected_type}\nFile Extension: {file_extension}\nSignature: {file_signature}\n\n"
        
        self.result_display.delete(1.0, tk.END)
        self.result_display.insert(tk.END, results)
        messagebox.showinfo("Batch Identification Completed", "Batch processing finished. Check results below.")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileTypeIdentifier(root)
    root.mainloop()