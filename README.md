import json
import os
import base64
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


# ─── CONSTANTS ────────────────────────────────────────────────────
VAULT_FILE  = "vault.json"
SALT_FILE   = "vault.salt"
PBKDF2_ITER = 480_000

APP_NAME = "VAULTEX"
APP_VERSION = "1.1.0"

PALETTE = {
    "bg": "#0f1117",
    "surface": "#1a1d27",
    "border": "#2a2d3e",
    "accent": "#4f8ef7",
    "accent2": "#6c63ff",
    "danger": "#e05c5c",
    "success": "#4caf82",
    "text": "#e8eaf0",
    "subtext": "#7b7f96",
    "row_even": "#1e2130",
    "row_odd": "#171a24",
}


# ─── CRYPTO ──────────────────────────────────────────────────────
def load_or_create_salt():
    if os.path.exists(SALT_FILE):
        return open(SALT_FILE, "rb").read()

    salt = secrets.token_bytes(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITER,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt(data: dict, key: bytes) -> bytes:
    return Fernet(key).encrypt(json.dumps(data).encode())


def decrypt(data: bytes, key: bytes) -> dict:
    return json.loads(Fernet(key).decrypt(data).decode())


def save_vault(entries, key):
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypt({"entries": entries}, key))


def load_vault(key):
    with open(VAULT_FILE, "rb") as f:
        return decrypt(f.read(), key).get("entries", [])


# ─── UI HELPERS ───────────────────────────────────────────────────
def copy_to_clipboard(app, text: str):
    app.clipboard_clear()
    app.clipboard_append(text)
    app.update()


# ─── MAIN APP ─────────────────────────────────────────────────────
class VaultexApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("900x620")
        self.configure(fg_color=PALETTE["bg"])

        self.salt = load_or_create_salt()
        self.key = None
        self.entries = []

        self._build_ui()
        self.withdraw()
        self.after(100, self._login)

    # ── LOGIN ────────────────────────────────────────────────────
    def _login(self):
        Login(self, self._on_login, self.salt)

    def _on_login(self, key):
        self.key = key
        self.entries = load_vault(key)
        self.deiconify()
        self._refresh()

    # ── UI ───────────────────────────────────────────────────────
    def _build_ui(self):
        self.sidebar = ctk.CTkFrame(self, width=200, fg_color=PALETTE["surface"])
        self.sidebar.pack(side="left", fill="y")

        self.main = ctk.CTkFrame(self, fg_color=PALETTE["bg"])
        self.main.pack(side="right", fill="both", expand=True)

        ctk.CTkButton(self.sidebar, text="Add", command=self._add).pack(pady=10)
        ctk.CTkButton(self.sidebar, text="Lock", command=self._lock).pack(pady=10)

        self.list_frame = ctk.CTkScrollableFrame(self.main)
        self.list_frame.pack(fill="both", expand=True, padx=20, pady=20)

    # ── TABLE ────────────────────────────────────────────────────
    def _refresh(self):
        for w in self.list_frame.winfo_children():
            w.destroy()

        for i, e in enumerate(self.entries):
            row = ctk.CTkFrame(self.list_frame, fg_color=PALETTE["row_even" if i % 2 == 0 else "row_odd"])
            row.pack(fill="x", pady=4)

            ctk.CTkLabel(row, text=e["service"], width=150, anchor="w").pack(side="left", padx=5)
            ctk.CTkLabel(row, text=e["username"], width=180, anchor="w").pack(side="left", padx=5)

            pw_label = ctk.CTkLabel(row, text="••••••••", width=120)
            pw_label.pack(side="left", padx=5)

            def toggle(pw=e["password"], label=pw_label):
                label.configure(text=pw if label.cget("text") == "••••••••" else "••••••••")

            pw_label.bind("<Button-1>", lambda e: toggle())

            # COPY BUTTON ADDED
            ctk.CTkButton(
                row,
                text="Copy",
                width=60,
                command=lambda p=e["password"]: copy_to_clipboard(self, p),
            ).pack(side="left", padx=5)

            ctk.CTkButton(
                row,
                text="Delete",
                fg_color=PALETTE["danger"],
                width=70,
                command=lambda idx=i: self._delete(idx),
            ).pack(side="right", padx=5)

    # ── CRUD ─────────────────────────────────────────────────────
    def _add(self):
        AddEntry(self, self._save)

    def _save(self, entry):
        self.entries.append(entry)
        save_vault(self.entries, self.key)
        self._refresh()

    def _delete(self, idx):
        self.entries.pop(idx)
        save_vault(self.entries, self.key)
        self._refresh()

    def _lock(self):
        self.withdraw()
        self._login()


# ─── LOGIN WINDOW ────────────────────────────────────────────────
class Login(ctk.CTkToplevel):
    def __init__(self, parent, callback, salt):
        super().__init__(parent)
        self.callback = callback
        self.salt = salt

        self.geometry("400x300")
        self.grab_set()

        self.entry = ctk.CTkEntry(self, show="*")
        self.entry.pack(pady=20)

        ctk.CTkButton(self, text="Unlock", command=self._unlock).pack()

    def _unlock(self):
        try:
            key = derive_key(self.entry.get(), self.salt)
            if os.path.exists(VAULT_FILE):
                load_vault(key)
            self.destroy()
            self.callback(key)
        except InvalidToken:
            messagebox.showerror("Error", "Wrong password")


# ─── ADD ENTRY ───────────────────────────────────────────────────
class AddEntry(ctk.CTkToplevel):
    def __init__(self, parent, callback):
        super().__init__(parent)
        self.callback = callback
        self.geometry("400x300")
        self.grab_set()

        self.service = ctk.CTkEntry(self)
        self.username = ctk.CTkEntry(self)
        self.password = ctk.CTkEntry(self)

        self.service.pack(pady=5)
        self.username.pack(pady=5)
        self.password.pack(pady=5)

        ctk.CTkButton(self, text="Save", command=self._save).pack()

    def _save(self):
        self.callback({
            "service": self.service.get(),
            "username": self.username.get(),
            "password": self.password.get(),
        })
        self.destroy()


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    app = VaultexApp()
    app.mainloop()
