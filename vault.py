import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3, os, base64, hashlib, secrets, string, shutil

import customtkinter as ctk
import pandas as pd
from cryptography.fernet import Fernet, InvalidToken
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.ticker import MaxNLocator

# ------------------------------------------------------------------ config
def _db_path():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    folder = os.path.join(base, "SecureVault")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "vault.db")
    if not os.path.exists(path) and os.path.exists("vault.db"):
        shutil.copy("vault.db", path)      # migrate the old local vault
    return path


DB = _db_path()
AUTO_LOCK_MIN = 5          # idle minutes before auto-lock
CLIP_CLEAR_SEC = 20        # clipboard auto-clear

BG, SIDE, CARD = "#0f1419", "#161b22", "#1c2330"
ACCENT, ACCENT_H = "#3b82f6", "#2563eb"
TEXT, MUTED = "#e6edf3", "#8b949e"
GOOD, WARN, BAD = "#22c55e", "#f59e0b", "#ef4444"

STRENGTH = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
SCOL = ["#ef4444", "#f97316", "#f59e0b", "#84cc16", "#22c55e", "#10b981"]

ctk.set_appearance_mode("dark")


# ------------------------------------------------------------------ helpers
def get_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB)")
    con.execute("""CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site TEXT, username TEXT, password BLOB, notes BLOB,
        created TEXT DEFAULT CURRENT_TIMESTAMP)""")
    return con


def derive_key(master, salt):
    k = hashlib.pbkdf2_hmac("sha256", master.encode(), salt, 200_000)
    return base64.urlsafe_b64encode(k)


def pw_score(pw):
    return sum([len(pw) >= 8, len(pw) >= 12,
                any(c.islower() for c in pw) and any(c.isupper() for c in pw),
                any(c.isdigit() for c in pw),
                any(c in string.punctuation for c in pw)])


def make_password(n=16, upper=True, digits=True, symbols=True):
    pools = [string.ascii_lowercase]
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*()-_=+")
    chars = "".join(pools)
    while True:
        pw = "".join(secrets.choice(chars) for _ in range(n))
        if all(any(c in p for c in pw) for p in pools):
            return pw


def btn(parent, text, command, kind="primary", **kw):
    colors = {
        "primary": (ACCENT, ACCENT_H),
        "ghost": (CARD, "#263043"),
        "danger": ("#7f1d1d", BAD),
    }[kind]
    return ctk.CTkButton(parent, text=text, command=command, fg_color=colors[0],
                         hover_color=colors[1], corner_radius=8, height=36,
                         font=("Segoe UI", 13, "bold" if kind == "primary" else "normal"), **kw)


# ------------------------------------------------------------------ login
class LoginFrame(ctk.CTkFrame):
    def __init__(self, master, on_success, con):
        super().__init__(master, fg_color=BG)
        self.con, self.on_success, self.tries = con, on_success, 0
        self.first = con.execute("SELECT v FROM meta WHERE k='salt'").fetchone() is None

        card = ctk.CTkFrame(self, fg_color=CARD, corner_radius=18)
        card.place(relx=.5, rely=.5, anchor="center")
        ctk.CTkLabel(card, text="🔐", font=("Segoe UI Emoji", 46)).pack(pady=(28, 0), padx=70)
        ctk.CTkLabel(card, text="Secure Vault", font=("Segoe UI", 26, "bold"),
                     text_color=TEXT).pack()
        ctk.CTkLabel(card, text="Create your master password" if self.first
                     else "Enter master password to unlock",
                     font=("Segoe UI", 13), text_color=MUTED).pack(pady=(2, 18))

        self.e1 = ctk.CTkEntry(card, show="•", width=300, height=42,
                               placeholder_text="Master password", corner_radius=10)
        self.e1.pack(padx=40)
        self.e2 = None
        if self.first:
            self.e2 = ctk.CTkEntry(card, show="•", width=300, height=42,
                                   placeholder_text="Confirm password", corner_radius=10)
            self.e2.pack(padx=40, pady=(10, 0))
            self.e2.bind("<Return>", lambda e: self.submit())

        self.show_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(card, text="Show password", variable=self.show_var,
                        command=self.toggle, text_color=MUTED,
                        font=("Segoe UI", 12)).pack(anchor="w", padx=40, pady=10)
        self.msg = ctk.CTkLabel(card, text="", text_color=BAD, font=("Segoe UI", 12))
        self.msg.pack()
        self.go = btn(card, "Create Vault" if self.first else "Unlock", self.submit, width=300)
        self.go.pack(padx=40, pady=(6, 30))
        self.e1.bind("<Return>", lambda e: self.submit())
        self.after(200, self.e1.focus)

    def toggle(self):
        ch = "" if self.show_var.get() else "•"
        self.e1.configure(show=ch)
        if self.e2:
            self.e2.configure(show=ch)

    def submit(self):
        pw = self.e1.get()
        if self.first:
            if len(pw) < 6:
                self.msg.configure(text="At least 6 characters required")
                return
            if pw != self.e2.get():
                self.msg.configure(text="Passwords do not match")
                return
            salt = os.urandom(16)
            f = Fernet(derive_key(pw, salt))
            self.con.execute("INSERT INTO meta VALUES ('salt', ?)", (salt,))
            self.con.execute("INSERT INTO meta VALUES ('check', ?)", (f.encrypt(b"vault-ok"),))
            self.con.commit()
            self.on_success(f)
            return

        salt = self.con.execute("SELECT v FROM meta WHERE k='salt'").fetchone()[0]
        check = self.con.execute("SELECT v FROM meta WHERE k='check'").fetchone()[0]
        f = Fernet(derive_key(pw, salt))
        try:
            f.decrypt(check)
        except InvalidToken:
            self.tries += 1
            self.e1.delete(0, "end")
            if self.tries >= 3:
                self.go.configure(state="disabled")
                self.msg.configure(text="Too many attempts. Wait 10 seconds...")
                self.after(10000, self.unlock_again)
            else:
                self.msg.configure(text=f"Wrong password ({3 - self.tries} tries left)")
            return
        self.on_success(f)

    def unlock_again(self):
        self.tries = 0
        self.go.configure(state="normal")
        self.msg.configure(text="")


# ------------------------------------------------------------------ add / edit dialog
class EntryDialog(ctk.CTkToplevel):
    def __init__(self, master, title, vals=("", "", "", "")):
        super().__init__(master)
        self.title(title)
        self.geometry("470x560")
        self.resizable(False, False)
        self.configure(fg_color=BG)
        self.transient(master)
        self.result = None

        ctk.CTkLabel(self, text=title, font=("Segoe UI", 21, "bold"),
                     text_color=TEXT).pack(anchor="w", padx=28, pady=(22, 8))
        self.site = self._field("Site / App", vals[0])
        self.user = self._field("Username / Email", vals[1])

        ctk.CTkLabel(self, text="Password", text_color=MUTED,
                     font=("Segoe UI", 12)).pack(anchor="w", padx=28, pady=(8, 2))
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=28)
        self.pw_var = tk.StringVar(value=vals[2])
        self.pw = ctk.CTkEntry(row, textvariable=self.pw_var, show="•", height=38)
        self.pw.pack(side="left", fill="x", expand=True)
        self.hidden = True
        ctk.CTkButton(row, text="👁", width=38, height=38, fg_color=CARD, hover_color="#263043",
                      command=self.toggle).pack(side="left", padx=(6, 0))
        ctk.CTkButton(row, text="Generate", width=80, height=38, fg_color=ACCENT,
                      hover_color=ACCENT_H, command=self.gen).pack(side="left", padx=(6, 0))

        self.bar = ctk.CTkProgressBar(self, height=8, corner_radius=4)
        self.bar.pack(fill="x", padx=28, pady=(10, 2))
        self.bar_lbl = ctk.CTkLabel(self, text="", font=("Segoe UI", 12), text_color=MUTED)
        self.bar_lbl.pack(anchor="w", padx=28)
        self.pw_var.trace_add("write", lambda *a: self.update_bar())
        self.update_bar()

        ctk.CTkLabel(self, text="Notes", text_color=MUTED,
                     font=("Segoe UI", 12)).pack(anchor="w", padx=28, pady=(8, 2))
        self.notes = ctk.CTkTextbox(self, height=80)
        self.notes.pack(fill="x", padx=28)
        self.notes.insert("1.0", vals[3])

        self.err = ctk.CTkLabel(self, text="", text_color=BAD, font=("Segoe UI", 12))
        self.err.pack(pady=(8, 0))
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x", padx=28, pady=8)
        btn(bar, "Save", self.save).pack(side="right")
        btn(bar, "Cancel", self.destroy, kind="ghost", width=90).pack(side="right", padx=8)
        self.after(150, self._grab)

    def _grab(self):
        try:
            self.grab_set()
            self.site.focus()
        except tk.TclError:
            pass

    def _field(self, label, value):
        ctk.CTkLabel(self, text=label, text_color=MUTED,
                     font=("Segoe UI", 12)).pack(anchor="w", padx=28, pady=(8, 2))
        e = ctk.CTkEntry(self, height=38)
        e.pack(fill="x", padx=28)
        e.insert(0, value)
        return e

    def toggle(self):
        self.hidden = not self.hidden
        self.pw.configure(show="•" if self.hidden else "")

    def gen(self):
        self.pw_var.set(make_password(16))
        self.hidden = False
        self.pw.configure(show="")

    def update_bar(self):
        pw = self.pw_var.get()
        s = pw_score(pw) if pw else 0
        self.bar.configure(progress_color=SCOL[s])
        self.bar.set(s / 5 if pw else 0)
        self.bar_lbl.configure(text=STRENGTH[s] if pw else "")

    def save(self):
        if not self.site.get().strip():
            self.err.configure(text="Site name is required")
            return
        if not self.pw_var.get():
            self.err.configure(text="Password is required")
            return
        self.result = [self.site.get().strip(), self.user.get().strip(),
                       self.pw_var.get(), self.notes.get("1.0", "end-1c").strip()]
        self.destroy()


# ------------------------------------------------------------------ main app
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Vault")
        self.geometry("1120x700")
        self.minsize(980, 620)
        self.configure(fg_color=BG)

        self.con = get_db()
        self.fernet = None
        self.df = pd.DataFrame()
        self.current = None
        self.idle_job = None
        self.clip_job = None
        self.reveal = False
        self.canvas = None

        for ev in ("<Key>", "<Button>", "<Motion>"):
            self.bind_all(ev, self.reset_idle, add="+")
        self.show_login()

    # ---------- screens ----------
    def show_login(self):
        self.fernet = None
        self.df = pd.DataFrame()
        if self.idle_job:
            self.after_cancel(self.idle_job)
            self.idle_job = None
        for w in self.winfo_children():
            if isinstance(w, ctk.CTkToplevel):
                w.destroy()
        if self.current:
            self.current.destroy()
        self.canvas = None
        self.current = LoginFrame(self, self.unlock, self.con)
        self.current.pack(fill="both", expand=True)

    def unlock(self, fernet):
        self.fernet = fernet
        self.current.destroy()
        self.current = ctk.CTkFrame(self, fg_color=BG)
        self.current.pack(fill="both", expand=True)
        self.build_main(self.current)
        self.reload()
        self.show_page("vault")
        self.reset_idle()

    def build_main(self, root):
        side = ctk.CTkFrame(root, fg_color=SIDE, width=230, corner_radius=0)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        ctk.CTkLabel(side, text="🔐  Secure Vault", font=("Segoe UI", 20, "bold"),
                     text_color=TEXT).pack(anchor="w", padx=22, pady=(28, 24))

        self.nav = {}
        for key, label in [("vault", "🗂   My Vault"), ("dashboard", "📊   Dashboard"),
                           ("generator", "🎲   Generator")]:
            b = ctk.CTkButton(side, text=label, anchor="w", height=42, corner_radius=8,
                              fg_color="transparent", hover_color=CARD,
                              font=("Segoe UI", 14), text_color=TEXT,
                              command=lambda k=key: self.show_page(k))
            b.pack(fill="x", padx=14, pady=3)
            self.nav[key] = b

        ctk.CTkLabel(side, text="EXPORT (unencrypted)", font=("Segoe UI", 10, "bold"),
                     text_color=MUTED).pack(anchor="w", padx=22, pady=(24, 4))
        for kind, label in [("csv", "⬇   CSV"), ("xlsx", "⬇   Excel")]:
            ctk.CTkButton(side, text=label, anchor="w", height=36, corner_radius=8,
                          fg_color="transparent", hover_color=CARD, text_color=MUTED,
                          font=("Segoe UI", 13),
                          command=lambda k=kind: self.export(k)).pack(fill="x", padx=14, pady=2)

        ctk.CTkLabel(side, text=f"Auto-lock: {AUTO_LOCK_MIN} min", font=("Segoe UI", 11),
                     text_color=MUTED).pack(side="bottom", pady=(0, 18))
        btn(side, "🔒  Lock Now", self.show_login, kind="danger").pack(
            side="bottom", fill="x", padx=16, pady=8)

        self.content = ctk.CTkFrame(root, fg_color=BG, corner_radius=0)
        self.content.pack(side="left", fill="both", expand=True)
        self.pages = {
            "vault": self.build_vault_page(),
            "dashboard": self.build_dashboard_page(),
            "generator": self.build_generator_page(),
        }

    def show_page(self, name):
        for f in self.pages.values():
            f.pack_forget()
        self.pages[name].pack(fill="both", expand=True, padx=26, pady=22)
        for k, b in self.nav.items():
            b.configure(fg_color=ACCENT if k == name else "transparent")
        if name == "dashboard":
            self.draw_dashboard()

    # ---------- data (pandas) ----------
    def load_df(self):
        rows = self.con.execute("SELECT id, site, username, password, notes FROM entries").fetchall()
        data = []
        for i, s, u, p, n in rows:
            try:
                pw = self.fernet.decrypt(p).decode()
                nt = self.fernet.decrypt(n).decode() if n else ""
            except InvalidToken:
                continue
            sc = pw_score(pw)
            data.append({"id": i, "site": s or "", "username": u or "", "password": pw,
                         "strength": STRENGTH[sc], "notes": nt, "score": sc})
        return pd.DataFrame(data, columns=["id", "site", "username", "password",
                                           "strength", "notes", "score"])

    def reload(self):
        self.df = self.load_df()
        self.refresh_table()

    # ---------- vault page ----------
    def build_vault_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        head = ctk.CTkFrame(page, fg_color="transparent")
        head.pack(fill="x")
        ctk.CTkLabel(head, text="My Vault", font=("Segoe UI", 26, "bold"),
                     text_color=TEXT).pack(side="left")
        btn(head, "＋  Add Entry", self.add).pack(side="right")
        self.search_entry = ctk.CTkEntry(head, width=260, height=36,
                                         placeholder_text="🔍  Search site, username, notes",
                                         corner_radius=10)
        self.search_entry.pack(side="right", padx=12)
        self.search_entry.bind("<KeyRelease>", lambda e: self.refresh_table())

        tools = ctk.CTkFrame(page, fg_color="transparent")
        tools.pack(fill="x", pady=(14, 10))
        btn(tools, "Copy Password", self.copy_password, kind="ghost").pack(side="left")
        btn(tools, "Copy Username", self.copy_username, kind="ghost").pack(side="left", padx=8)
        btn(tools, "Edit", self.edit, kind="ghost", width=70).pack(side="left")
        btn(tools, "Delete", self.delete, kind="danger", width=80).pack(side="left", padx=8)
        self.reveal_btn = btn(tools, "👁  Show Passwords", self.toggle_reveal, kind="ghost")
        self.reveal_btn.pack(side="right")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                        rowheight=36, borderwidth=0, font=("Segoe UI", 11))
        style.configure("Treeview.Heading", background=SIDE, foreground=TEXT, relief="flat",
                        font=("Segoe UI", 11, "bold"), padding=8)
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        style.map("Treeview", background=[("selected", ACCENT)],
                  foreground=[("selected", "white")])
        style.map("Treeview.Heading", background=[("active", SIDE)])

        box = ctk.CTkFrame(page, fg_color=CARD, corner_radius=12)
        box.pack(fill="both", expand=True)
        cols = ("id", "site", "username", "password", "strength", "notes")
        self.tree = ttk.Treeview(box, columns=cols, show="headings",
                                 displaycolumns=cols[1:], selectmode="browse")
        widths = {"site": 190, "username": 200, "password": 160, "strength": 110, "notes": 260}
        for c in cols[1:]:
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.tag_configure("bad", foreground="#f87171")
        self.tree.tag_configure("warn", foreground="#fbbf24")
        self.tree.tag_configure("good", foreground="#4ade80")
        sb = ctk.CTkScrollbar(box, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y", pady=6, padx=(0, 4))
        self.tree.pack(fill="both", expand=True, padx=(8, 0), pady=8)
        self.tree.bind("<Double-1>", lambda e: self.copy_password())

        self.status = ctk.CTkLabel(page, text="", text_color=MUTED, font=("Segoe UI", 12))
        self.status.pack(anchor="w", pady=(8, 0))
        return page

    def refresh_table(self):
        df = self.df
        q = self.search_entry.get().strip()
        if q and not df.empty:
            m = (df["site"].str.contains(q, case=False, regex=False)
                 | df["username"].str.contains(q, case=False, regex=False)
                 | df["notes"].str.contains(q, case=False, regex=False))
            df = df[m]
        self.tree.delete(*self.tree.get_children())
        for r in df.itertuples():
            pw = r.password if self.reveal else "•" * 10
            tag = "bad" if r.score <= 1 else "warn" if r.score <= 3 else "good"
            self.tree.insert("", "end", tags=(tag,), values=(
                r.id, r.site, r.username, pw, r.strength, r.notes.replace("\n", " ")))
        self.status.configure(text=f"{len(df)} of {len(self.df)} entries  •  "
                                   f"double-click a row to copy its password")

    def toggle_reveal(self):
        self.reveal = not self.reveal
        self.reveal_btn.configure(text="🙈  Hide Passwords" if self.reveal else "👁  Show Passwords")
        self.refresh_table()

    def selected_row(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Select a row first")
            return None
        i = int(self.tree.item(sel[0])["values"][0])
        return self.df[self.df["id"] == i].iloc[0]

    # ---------- clipboard ----------
    def copy_text(self, text, what):
        self.clipboard_clear()
        self.clipboard_append(text)
        if self.clip_job:
            self.after_cancel(self.clip_job)
        self.clip_job = self.after(CLIP_CLEAR_SEC * 1000, self.clipboard_clear)
        self.status.configure(text=f"✔ {what} copied. Clipboard clears in {CLIP_CLEAR_SEC}s")

    def copy_password(self):
        r = self.selected_row()
        if r is not None:
            self.copy_text(r["password"], "Password")

    def copy_username(self):
        r = self.selected_row()
        if r is not None:
            self.copy_text(r["username"], "Username")

    # ---------- CRUD ----------
    def ask_entry(self, title, vals=("", "", "", "")):
        dlg = EntryDialog(self, title, vals)
        self.wait_window(dlg)
        return dlg.result

    def add(self):
        v = self.ask_entry("Add Entry")
        if v:
            self.con.execute(
                "INSERT INTO entries (site, username, password, notes) VALUES (?,?,?,?)",
                (v[0], v[1], self.fernet.encrypt(v[2].encode()), self.fernet.encrypt(v[3].encode())))
            self.con.commit()
            self.reload()

    def edit(self):
        r = self.selected_row()
        if r is None:
            return
        v = self.ask_entry("Edit Entry", (r["site"], r["username"], r["password"], r["notes"]))
        if v:
            self.con.execute(
                "UPDATE entries SET site=?, username=?, password=?, notes=? WHERE id=?",
                (v[0], v[1], self.fernet.encrypt(v[2].encode()),
                 self.fernet.encrypt(v[3].encode()), int(r["id"])))
            self.con.commit()
            self.reload()

    def delete(self):
        r = self.selected_row()
        if r is None:
            return
        if messagebox.askyesno("Delete", f"Delete '{r['site']}' ?"):
            self.con.execute("DELETE FROM entries WHERE id=?", (int(r["id"]),))
            self.con.commit()
            self.reload()

    # ---------- dashboard ----------
    def build_dashboard_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        ctk.CTkLabel(page, text="Security Dashboard", font=("Segoe UI", 26, "bold"),
                     text_color=TEXT).pack(anchor="w")

        cards = ctk.CTkFrame(page, fg_color="transparent")
        cards.pack(fill="x", pady=16)
        self.stat = {}
        for i, (key, title, color) in enumerate([("total", "Total Entries", ACCENT),
                                                  ("strong", "Strong", GOOD),
                                                  ("weak", "Weak", WARN),
                                                  ("reused", "Reused", BAD)]):
            cards.grid_columnconfigure(i, weight=1)
            c = ctk.CTkFrame(cards, fg_color=CARD, corner_radius=14)
            c.grid(row=0, column=i, padx=6, sticky="ew")
            ctk.CTkLabel(c, text=title, text_color=MUTED,
                         font=("Segoe UI", 12)).pack(anchor="w", padx=18, pady=(14, 0))
            lbl = ctk.CTkLabel(c, text="0", text_color=color, font=("Segoe UI", 34, "bold"))
            lbl.pack(anchor="w", padx=18, pady=(0, 12))
            self.stat[key] = lbl

        row = ctk.CTkFrame(page, fg_color="transparent")
        row.pack(fill="both", expand=True)
        row.grid_columnconfigure(0, weight=3)
        row.grid_columnconfigure(1, weight=2)
        row.grid_rowconfigure(0, weight=1)
        self.chart_holder = ctk.CTkFrame(row, fg_color=CARD, corner_radius=14)
        self.chart_holder.grid(row=0, column=0, sticky="nsew", padx=6)
        right = ctk.CTkFrame(row, fg_color=CARD, corner_radius=14)
        right.grid(row=0, column=1, sticky="nsew", padx=6)
        ctk.CTkLabel(right, text="⚠  Needs attention", font=("Segoe UI", 15, "bold"),
                     text_color=TEXT).pack(anchor="w", padx=18, pady=(16, 6))
        self.attn = ctk.CTkTextbox(right, fg_color="transparent", font=("Segoe UI", 13),
                                   text_color=TEXT)
        self.attn.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        return page

    def draw_dashboard(self):
        df = self.df
        total = len(df)
        if total:
            strong = int((df["score"] >= 4).sum())
            weak = int((df["score"] <= 2).sum())
            reused_mask = df["password"].duplicated(keep=False)
            reused = int(reused_mask.sum())
        else:
            strong = weak = reused = 0
            reused_mask = None
        for k, v in zip(("total", "strong", "weak", "reused"), (total, strong, weak, reused)):
            self.stat[k].configure(text=str(v))

        counts = (df["strength"].value_counts().reindex(STRENGTH, fill_value=0)
                  if total else pd.Series(0, index=STRENGTH))
        fig = Figure(figsize=(5, 3.4), dpi=100, facecolor=CARD)
        ax = fig.add_subplot(111)
        ax.set_facecolor(CARD)
        ax.bar(range(len(STRENGTH)), counts.values, color=SCOL, width=0.6)
        ax.set_xticks(range(len(STRENGTH)))
        ax.set_xticklabels(STRENGTH, fontsize=8, color=MUTED)
        ax.tick_params(axis="y", colors=MUTED, labelsize=8)
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
        ax.set_title("Password strength", color=TEXT, fontsize=12, loc="left")
        for s in ax.spines.values():
            s.set_visible(False)
        ax.grid(axis="y", color="#263043", linewidth=0.6)
        ax.set_axisbelow(True)
        fig.tight_layout()
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        self.canvas = FigureCanvasTkAgg(fig, master=self.chart_holder)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)
        self.canvas.draw()

        self.attn.configure(state="normal")
        self.attn.delete("1.0", "end")
        lines = []
        if total:
            for r in df.itertuples():
                if r.score <= 2:
                    lines.append(f"•  {r.site}  —  {r.strength}")
            for site in df[reused_mask]["site"].tolist():
                lines.append(f"🔁  {site}  —  reused password")
        self.attn.insert("1.0", "\n".join(lines) if lines else "✔ Everything looks good!")
        self.attn.configure(state="disabled")

    # ---------- generator ----------
    def build_generator_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        ctk.CTkLabel(page, text="Password Generator", font=("Segoe UI", 26, "bold"),
                     text_color=TEXT).pack(anchor="w")
        card = ctk.CTkFrame(page, fg_color=CARD, corner_radius=14)
        card.pack(fill="x", pady=18)

        self.gen_out = ctk.CTkEntry(card, height=52, font=("Consolas", 20), justify="center")
        self.gen_out.pack(fill="x", padx=24, pady=(24, 10))
        self.gen_bar = ctk.CTkProgressBar(card, height=8)
        self.gen_bar.pack(fill="x", padx=24)
        self.gen_lbl = ctk.CTkLabel(card, text="", text_color=MUTED)
        self.gen_lbl.pack(pady=(4, 12))

        self.gen_len = tk.IntVar(value=16)
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=24)
        ctk.CTkLabel(top, text="Length", text_color=MUTED).pack(side="left")
        self.len_lbl = ctk.CTkLabel(top, text="16", text_color=TEXT, font=("Segoe UI", 14, "bold"))
        self.len_lbl.pack(side="right")
        ctk.CTkSlider(card, from_=8, to=32, number_of_steps=24, variable=self.gen_len,
                      command=lambda v: (self.len_lbl.configure(text=str(int(v))),
                                         self.generate())).pack(fill="x", padx=24, pady=8)

        self.opt_up = tk.BooleanVar(value=True)
        self.opt_dg = tk.BooleanVar(value=True)
        self.opt_sy = tk.BooleanVar(value=True)
        opts = ctk.CTkFrame(card, fg_color="transparent")
        opts.pack(fill="x", padx=24, pady=8)
        for text, var in [("Uppercase", self.opt_up), ("Numbers", self.opt_dg),
                          ("Symbols", self.opt_sy)]:
            ctk.CTkCheckBox(opts, text=text, variable=var, command=self.generate,
                            text_color=TEXT).pack(side="left", padx=(0, 22))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=(10, 24))
        btn(row, "🎲  Generate", self.generate).pack(side="left")
        btn(row, "Copy", lambda: self.copy_gen(), kind="ghost", width=90).pack(side="left", padx=10)
        self.generate()
        return page

    def generate(self):
        pw = make_password(int(self.gen_len.get()), self.opt_up.get(),
                           self.opt_dg.get(), self.opt_sy.get())
        self.gen_out.delete(0, "end")
        self.gen_out.insert(0, pw)
        s = pw_score(pw)
        self.gen_bar.configure(progress_color=SCOL[s])
        self.gen_bar.set(s / 5)
        self.gen_lbl.configure(text=STRENGTH[s])

    def copy_gen(self):
        self.clipboard_clear()
        self.clipboard_append(self.gen_out.get())
        self.gen_lbl.configure(text="✔ Copied")

    # ---------- export ----------
    def export(self, kind):
        if self.df.empty:
            messagebox.showinfo("Export", "Nothing to export")
            return
        if not messagebox.askokcancel("Warning",
                                      "Export is NOT encrypted. Keep the file safe!"):
            return
        path = filedialog.asksaveasfilename(defaultextension=f".{kind}",
                                            filetypes=[(kind.upper(), f"*.{kind}")])
        if not path:
            return
        out = self.df.drop(columns=["score"])
        if kind == "csv":
            out.to_csv(path, index=False)
        else:
            out.to_excel(path, index=False)
        messagebox.showinfo("Done", f"Saved to {path}")

    # ---------- auto-lock ----------
    def reset_idle(self, event=None):
        if self.fernet is None:
            return
        if self.idle_job:
            self.after_cancel(self.idle_job)
        self.idle_job = self.after(AUTO_LOCK_MIN * 60 * 1000, self.show_login)


if __name__ == "__main__":
    App().mainloop()