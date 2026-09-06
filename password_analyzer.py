"""
🔐 Password Strength Analyzer
════════════════════════════════════════════════════════════════
Features
  • Live analysis of length, complexity & entropy
  • Common-password, keyboard-pattern & sequence detection
  • "Time to crack" estimate
  • Dynamic suggestions + secure password/passphrase generator
  • SQLite vault (SHA-256 hashes) that blocks password reuse

Run:  python password_analyzer.py
"""

import hashlib
import math
import re
import secrets
import sqlite3
import string
import tkinter as tk
from tkinter import messagebox
from datetime import datetime

# ══════════════════════════════════════════════════════════════
#  DATA
# ══════════════════════════════════════════════════════════════

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "password1", "111111", "123123", "qwerty123",
    "monkey", "dragon", "iloveyou", "000000", "123321", "654321",
    "666666", "123qwe", "1q2w3e4r", "qwertyuiop", "sunshine", "princess",
    "letmein", "welcome", "admin", "admin123", "root", "toor",
    "pass123", "test123", "football", "baseball", "master", "hello123",
    "freedom", "whatever", "trustno1", "batman", "superman", "michael",
    "hunter", "ranger", "harley", "summer", "winter", "asdfgh",
    "zxcvbnm", "asdf1234", "qazwsx", "starwars", "pokemon", "sunset",
    "password123", "p@ssw0rd", "passw0rd", "secret", "google", "facebook",
}

KEYBOARD_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")

WORDS = (
    "amber wolf river storm tiger cloud stone eagle forest maple "
    "silver golden thunder crystal shadow phoenix galaxy nebula falcon dragon "
    "comet orbit quantum vector lunar solar cosmic pixel cipher matrix "
    "harbor meadow canyon breeze summit glacier ember frost willow cobalt "
    "cedar raven sparrow badger lynx panther otter heron bison viper "
    "kernel byte stack token proxy cache shard node query script "
    "beacon anchor compass jetty sail tide coral reef pearl drift "
    "aurora zenith eclipse horizon nova pulsar quasar meteor stardust void "
    "jasper onyx topaz beryl garnet opal quartz marble granite slate "
    "vega sirius rigel altair deneb polaris arcturus antares capella mira"
).split()

SYMBOL_POOL = "!@#$%^&*()-_=+[]{}?"

# ══════════════════════════════════════════════════════════════
#  CORE: ANALYZER + GENERATORS
# ══════════════════════════════════════════════════════════════

class PasswordAnalyzer:
    WEAK_WORDS = ("password", "passwd", "admin", "user", "login", "welcome", "letmein")

    def analyze(self, pw: str) -> dict:
        length = len(pw)
        has_lower  = any(c.islower() for c in pw)
        has_upper  = any(c.isupper() for c in pw)
        has_digit  = any(c.isdigit() for c in pw)
        has_symbol = any(not c.isalnum() for c in pw)

        charset = 26 * has_lower + 26 * has_upper + 10 * has_digit
        charset += 33 if has_symbol else 0
        if any(not c.isascii() for c in pw):
            charset += 100

        entropy = length * math.log2(charset) if charset else 0.0
        lowered = pw.lower()

        is_common  = lowered in COMMON_PASSWORDS
        has_seq    = self._ordered_sequence(lowered) or self._keyboard_sequence(lowered)
        has_repeat = bool(re.search(r"(.)\1{2,}", pw)) or bool(re.search(r"(.{3,})\1", pw))
        weak_word  = any(w in lowered for w in self.WEAK_WORDS)

        penalties = 0
        if is_common:
            entropy = min(entropy, 10);            penalties += 1
        if weak_word:
            entropy *= 0.70;                       penalties += 1
        if has_seq:
            entropy *= 0.65;                       penalties += 1
        if has_repeat:
            entropy *= 0.75;                       penalties += 1

        variety = sum((has_lower, has_upper, has_digit, has_symbol))
        if length == 0:
            score = 0
        else:
            score  = min(30.0, length * 2.0)                 # length
            score += variety * 8.0                           # complexity
            score += max(0.0, min(38.0, (entropy - 25) * 0.55))  # unpredictability
            score -= 12 * penalties
            if is_common:
                score = min(score, 6)
            score = int(max(0, min(100, round(score))))

        return {"length": length, "has_lower": has_lower, "has_upper": has_upper,
                "has_digit": has_digit, "has_symbol": has_symbol, "entropy": entropy,
                "score": score, "is_common": is_common, "has_sequence": has_seq,
                "has_repeat": has_repeat}

    # ── pattern detectors ────────────────────────────────────
    @staticmethod
    def _ordered_sequence(s):
        for i in range(len(s) - 2):
            a, b, c = ord(s[i]), ord(s[i+1]), ord(s[i+2])
            if (b - a == 1 and c - b == 1) or (a - b == 1 and b - c == 1):
                return True
        return False

    @staticmethod
    def _keyboard_sequence(s):
        for row in KEYBOARD_ROWS:
            for i in range(len(row) - 2):
                chunk = row[i:i+3]
                if chunk in s or chunk[::-1] in s:
                    return True
        return False

    # ── dynamic suggestions ──────────────────────────────────
    def suggestions(self, rep: dict) -> list:
        tips = []
        if rep["length"] < 12:
            tips.append(f"Make it at least 12 characters (currently {rep['length']}).")
        if not rep["has_lower"]:  tips.append("Add lowercase letters (a-z).")
        if not rep["has_upper"]:  tips.append("Add uppercase letters (A-Z).")
        if not rep["has_digit"]:  tips.append("Add at least one number (0-9).")
        if not rep["has_symbol"]: tips.append("Add a special character such as ! @ # $ %.")
        if rep["is_common"]:      tips.append("Never use passwords found in public leak lists.")
        if rep["has_sequence"]:   tips.append("Avoid predictable sequences like '1234' or 'qwerty'.")
        if rep["has_repeat"]:     tips.append("Avoid repeated characters or word blocks.")
        return tips


def generate_password(length: int = 16) -> str:
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOL_POOL]
    chars = [secrets.choice(p) for p in pools]                      # guarantee all classes
    chars += [secrets.choice("".join(pools)) for _ in range(length - 4)]
    out = []
    while chars:                                                    # cryptographically safe shuffle
        out.append(chars.pop(secrets.randbelow(len(chars))))
    return "".join(out)


def generate_passphrase(words: int = 5) -> str:
    parts = [secrets.choice(WORDS).capitalize() for _ in range(words)]
    parts.append(str(secrets.randbelow(90) + 10))
    parts.append(secrets.choice(SYMBOL_POOL))
    return "-".join(parts)


YEAR = 31_556_952

def crack_time_text(entropy_bits: float) -> str:
    if entropy_bits <= 0:
        return "instantly"
    seconds = (2.0 ** min(entropy_bits, 119)) / 1e10        # 10 billion guesses/sec
    if entropy_bits >= 120 or seconds >= YEAR * 1e12:
        return "trillions of years 🔒"
    steps = [(YEAR * 1e9, "billion years"), (YEAR * 1e6, "million years"),
             (YEAR, "years"), (2_629_746, "months"), (86_400, "days"),
             (3_600, "hours"), (60, "minutes"), (1, "seconds")]
    for size, name in steps:
        if seconds >= size:
            n = seconds / size
            label = name if round(n) != 1 else name.replace("years", "year") \
                .replace("months", "month").replace("days", "day").replace("hours", "hour") \
                .replace("minutes", "minute").replace("seconds", "second")
            return f"~{n:,.0f} {label}" if n >= 10 else f"~{n:.1f} {label}"
    return "instantly"


def verdict_of(score: int):
    if score >= 85: return "VERY STRONG", "#2ed573"
    if score >= 70: return "STRONG",      "#7bed9f"
    if score >= 50: return "FAIR",        "#f6c445"
    if score >= 30: return "WEAK",        "#ff9f43"
    return "VERY WEAK", "#ff5c5c"

# ══════════════════════════════════════════════════════════════
#  DATABASE: REUSE PREVENTION (stores hashes only)
# ══════════════════════════════════════════════════════════════

class PasswordVault:
    """Remembers SHA-256 hashes so old passwords can't be reused.
    Demo-grade: production systems should use bcrypt/argon2."""

    def __init__(self, path: str = "password_vault.db"):
        self.conn = sqlite3.connect(path)
        self.conn.execute("""CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                pw_hash  TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (username, pw_hash))""")
        self.conn.commit()

    @staticmethod
    def _hash(username: str, password: str) -> str:
        return hashlib.sha256(f"{username.strip().lower()}::{password}".encode()).hexdigest()

    def was_used_before(self, username: str, password: str):
        """Return the date it was last used, or None."""
        row = self.conn.execute(
            "SELECT created_at FROM password_history WHERE username=? AND pw_hash=?",
            (username.strip().lower(), self._hash(username, password))).fetchone()
        return row[0] if row else None

    def save(self, username: str, password: str) -> bool:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO password_history (username, pw_hash, created_at) VALUES (?,?,?)",
            (username.strip().lower(), self._hash(username, password),
             datetime.now().strftime("%Y-%m-%d %H:%M")))
        self.conn.commit()
        return cur.rowcount > 0

    def stats(self, username: str):
        row = self.conn.execute(
            "SELECT COUNT(*), MAX(created_at) FROM password_history WHERE username=?",
            (username.strip().lower(),)).fetchone()
        return row[0] or 0, row[1]

# ══════════════════════════════════════════════════════════════
#  UI
# ══════════════════════════════════════════════════════════════

BG, CARD, FIELD = "#0f1220", "#191d33", "#232848"
TEXT, MUTED, DIM = "#eceef8", "#8b91b5", "#262b4a"
ACCENT, GREEN, ORANGE = "#6c5ce7", "#2ed573", "#ff9f43"
FONT = "Segoe UI"
METER_W, METER_H, SEGS = 636, 12, 32
GRADIENT = ("#ff5c5c", "#ff9f43", "#f6c445", "#7bed9f", "#2ed573")

CHECKS = [
    ("At least 12 characters",         lambda r: r["length"] >= 12),
    ("Lower & uppercase letters",      lambda r: r["has_lower"] and r["has_upper"]),
    ("Contains numbers",               lambda r: r["has_digit"]),
    ("Contains special characters",    lambda r: r["has_symbol"]),
    ("Not a leaked / common password", lambda r: not r["is_common"]),
    ("No sequences or repeats",        lambda r: not (r["has_sequence"] or r["has_repeat"])),
]


def _mix(c1, c2, t):
    r = round(int(c1[1:3], 16) + (int(c2[1:3], 16) - int(c1[1:3], 16)) * t)
    g = round(int(c1[3:5], 16) + (int(c2[3:5], 16) - int(c1[3:5], 16)) * t)
    b = round(int(c1[5:7], 16) + (int(c2[5:7], 16) - int(c1[5:7], 16)) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def meter_color(t: float) -> str:
    t = max(0.0, min(1.0, t))
    pos = t * (len(GRADIENT) - 1)
    i = min(int(pos), len(GRADIENT) - 2)
    return _mix(GRADIENT[i], GRADIENT[i + 1], pos - i)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.analyzer = PasswordAnalyzer()
        self.vault = PasswordVault()
        self.visible = False
        self._display_score, self._target, self._anim_job = 0.0, 0, None

        self.title("Password Strength Analyzer")
        self.configure(bg=BG)
        self.resizable(False, False)
        self._center(740, 800)
        self._build()
        self._refresh()

    # ── layout ───────────────────────────────────────────────
    def _center(self, w, h):
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _button(self, parent, text, cmd, bg=ACCENT, fg="#ffffff"):
        btn = tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg,
                        activebackground=bg, activeforeground=fg, relief="flat",
                        bd=0, font=(FONT, 9, "bold"), padx=14, pady=8, cursor="hand2")
        btn.bind("<Enter>", lambda e: btn.config(bg=_mix(bg, "#ffffff", 0.18)))
        btn.bind("<Leave>", lambda e: btn.config(bg=bg))
        return btn

    def _build(self):
        tk.Label(self, text="🔐  Password Strength Analyzer", font=(FONT, 21, "bold"),
                 bg=BG, fg=TEXT).pack(pady=(22, 2))
        tk.Label(self, text="Length · complexity · uniqueness — with stronger alternatives",
                 font=(FONT, 10), bg=BG, fg=MUTED).pack(pady=(0, 14))

        # ── input + meter card ───────────────────────────────
        card = tk.Frame(self, bg=CARD)
        card.pack(padx=28, fill="x")
        inner = tk.Frame(card, bg=CARD)
        inner.pack(padx=22, pady=18)
        inner.columnconfigure(0, weight=1)

        def field_label(text, row):
            tk.Label(inner, text=text, font=(FONT, 9, "bold"), bg=CARD, fg=MUTED
                     ).grid(row=row, column=0, sticky="w", pady=(0, 4))

        field_label("USERNAME", 0)
        self.username_var = tk.StringVar()
        tk.Entry(inner, textvariable=self.username_var, font=(FONT, 12), bg=FIELD,
                 fg=TEXT, insertbackground=TEXT, relief="flat", width=44
                 ).grid(row=1, column=0, sticky="ew", ipady=8)

        field_label("PASSWORD", 2)
        self.password_var = tk.StringVar()
        prow = tk.Frame(inner, bg=CARD)
        prow.grid(row=3, column=0, sticky="ew", pady=(0, 4))
        self.pw_entry = tk.Entry(prow, textvariable=self.password_var, font=(FONT, 13),
                                 bg=FIELD, fg=TEXT, insertbackground=TEXT,
                                 relief="flat", show="•")
        self.pw_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 8))
        self.pw_entry.focus()
        self.eye_btn = self._button(prow, "👁  SHOW", self._toggle, bg=FIELD, fg=MUTED)
        self.eye_btn.pack(side="right")

        self.meter = tk.Canvas(inner, width=METER_W, height=METER_H, bg=CARD,
                               highlightthickness=0)
        self.meter.grid(row=4, column=0, sticky="ew", pady=(16, 6))
        self.score_lbl = tk.Label(inner, text="", font=(FONT, 13, "bold"), bg=CARD, fg=MUTED)
        self.score_lbl.grid(row=5, column=0, sticky="w")

        stats = tk.Frame(inner, bg=CARD)
        stats.grid(row=6, column=0, sticky="ew", pady=(8, 0))
        self.entropy_val = self._stat(stats, "ENTROPY", 0)
        self.crack_val = self._stat(stats, "TIME TO CRACK (offline, 10¹⁰ guesses/s)", 1)

        # ── requirements card ────────────────────────────────
        chk_card = tk.Frame(self, bg=CARD)
        chk_card.pack(padx=28, pady=(14, 0), fill="x")
        chk = tk.Frame(chk_card, bg=CARD)
        chk.pack(padx=22, pady=14)
        tk.Label(chk, text="REQUIREMENTS", font=(FONT, 9, "bold"), bg=CARD, fg=MUTED
                 ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        self.check_lbls = []
        for i, (label, _) in enumerate(CHECKS):
            lbl = tk.Label(chk, text="", font=(FONT, 10), bg=CARD, fg=MUTED, anchor="w")
            lbl.grid(row=i // 2 + 1, column=i % 2, sticky="w", padx=(0, 30), pady=2)
            self.check_lbls.append(lbl)

        # ── suggestions card ─────────────────────────────────
        sug_card = tk.Frame(self, bg=CARD)
        sug_card.pack(padx=28, pady=(14, 0), fill="x")
        sug = tk.Frame(sug_card, bg=CARD)
        sug.pack(padx=22, pady=14, fill="x")
        tk.Label(sug, text="💡  SUGGESTIONS", font=(FONT, 9, "bold"), bg=CARD, fg=MUTED
                 ).pack(anchor="w", pady=(0, 6))
        self.sug_box = tk.Text(sug, height=6, wrap="word", relief="flat", bg=FIELD,
                               fg=TEXT, font=(FONT, 10), padx=12, pady=10, highlightthickness=0)
        self.sug_box.tag_config("warn", foreground=ORANGE)
        self.sug_box.tag_config("ok", foreground=GREEN)
        self.sug_box.pack(fill="x")
        self.sug_box.config(state="disabled")

        # ── action buttons ───────────────────────────────────
        bar = tk.Frame(self, bg=BG)
        bar.pack(pady=16)
        for text, cmd, bg, fg in [
            ("🎲  GENERATE",       self._gen_password,   ACCENT, "#fff"),
            ("💬  PASSPHRASE",     self._gen_passphrase, ACCENT, "#fff"),
            ("📋  COPY",           self._copy,           "#2f3557", "#fff"),
            ("💾  SAVE TO VAULT",  self._save,           GREEN, BG),
            ("🕘  HISTORY",        self._history,        "#2f3557", "#fff"),
        ]:
            self._button(bar, text, cmd, bg, fg).pack(side="left", padx=5)

        self.status_lbl = tk.Label(self, text="Ready — start typing a password.",
                                   font=(FONT, 9), bg=BG, fg=MUTED)
        self.status_lbl.pack(side="bottom", pady=(0, 10))

        self.password_var.trace_add("write", self._refresh)
        self.username_var.trace_add("write", self._refresh)

    def _stat(self, parent, title, col):
        f = tk.Frame(parent, bg=CARD)
        f.grid(row=0, column=col, sticky="w", padx=(0, 40))
        tk.Label(f, text=title, font=(FONT, 8, "bold"), bg=CARD, fg=MUTED).pack(anchor="w")
        val = tk.Label(f, text="—", font=(FONT, 12, "bold"), bg=CARD, fg=TEXT)
        val.pack(anchor="w")
        return val

    # ── live analysis ────────────────────────────────────────
    def _refresh(self, *_):
        pw = self.password_var.get()
        user = self.username_var.get().strip()
        rep = self.analyzer.analyze(pw)

        if rep["length"] == 0:
            self.score_lbl.config(text="Type a password to analyse it…", fg=MUTED)
        else:
            name, col = verdict_of(rep["score"])
            self.score_lbl.config(text=f"{name}   ·   {rep['score']} / 100", fg=col)
        self._animate(rep["score"])

        self.entropy_val.config(text=f"{rep['entropy']:.0f} bits" if pw else "—")
        self.crack_val.config(text=crack_time_text(rep["entropy"]) if pw else "—")

        for (label, fn), lbl in zip(CHECKS, self.check_lbls):
            ok = fn(rep)
            lbl.config(text=f"{'✔' if ok else '✘'}  {label}", fg=GREEN if ok else "#565d85")

        tips = self.analyzer.suggestions(rep)
        if user and user.lower() in pw.lower():
            tips.insert(0, "Don't include your username inside the password.")
        reused = self.vault.was_used_before(user, pw) if user else None
        if reused:
            tips.insert(0, f"REUSED PASSWORD — you already used this one on {reused}.")
        self._render_tips(tips, strong=rep["score"] >= 70 and not tips)

    def _render_tips(self, tips, strong):
        box = self.sug_box
        box.config(state="normal")
        box.delete("1.0", "end")
        if strong:
            box.insert("end", "✔  Solid password — no issues found. Store it in a password manager.", "ok")
        else:
            if not tips:
                tips = ["Try a passphrase: long random words are memorable and hard to crack (hit 💬 PASSPHRASE)."]
            for tip in tips:
                box.insert("end", "•  ")
                box.insert("end", tip + "\n", "warn" if tip.startswith(("REUSED", "Never")) else ())
        box.config(state="disabled")

    # ── animated strength meter ──────────────────────────────
    def _animate(self, target):
        self._target = target
        if self._anim_job is None:
            self._anim_step()

    def _anim_step(self):
        diff = self._target - self._display_score
        if abs(diff) < 0.6:
            self._display_score, self._anim_job = float(self._target), None
            self._paint_meter(self._display_score)
            return
        self._display_score += diff * 0.28
        self._paint_meter(self._display_score)
        self._anim_job = self.after(15, self._anim_step)

    def _paint_meter(self, value):
        c = self.meter
        c.delete("all")
        gap = 3
        seg_w = (METER_W - gap * (SEGS - 1)) / SEGS
        fill = SEGS * value / 100.0
        for i in range(SEGS):
            x = i * (seg_w + gap)
            if i < fill:
                c.create_rectangle(x, 0, x + seg_w, METER_H,
                                   fill=meter_color((i + 1) / SEGS), outline="")
            elif i < fill + 1 and fill - i > 0.05:
                c.create_rectangle(x, 0, x + seg_w * (fill - i), METER_H,
                                   fill=meter_color((i + 1) / SEGS), outline="")
            else:
                c.create_rectangle(x, 0, x + seg_w, METER_H, fill=DIM, outline="")

    # ── actions ──────────────────────────────────────────────
    def _toggle(self):
        self.visible = not self.visible
        self.pw_entry.config(show="" if self.visible else "•")
        self.eye_btn.config(text="🙈  HIDE" if self.visible else "👁  SHOW")

    def _gen_password(self):
        self.password_var.set(generate_password(16))
        self.status("🎲 Generated a random 16-character password.")

    def _gen_passphrase(self):
        self.password_var.set(generate_passphrase())
        self.status("💬 Generated a memorable passphrase.")

    def _copy(self):
        if not self.password_var.get():
            return self.status("Nothing to copy yet.")
        self.clipboard_clear()
        self.clipboard_append(self.password_var.get())
        self.status("📋 Password copied to clipboard.")

    def _save(self):
        user, pw = self.username_var.get().strip(), self.password_var.get()
        if not user:
            messagebox.showwarning("Username needed", "Enter a username — the vault stores hashes per user.")
            return
        if not pw:
            messagebox.showwarning("Nothing to save", "Type or generate a password first.")
            return
        if self.vault.was_used_before(user, pw):
            messagebox.showerror("Password reuse blocked",
                                 "⚠ This exact password is already in your history.\nChoose a brand-new one.")
            return
        if self.analyzer.analyze(pw)["score"] < 60:
            if not messagebox.askyesno("Weak password",
                                       f"Score is low. Save it anyway?"):
                return
        self.vault.save(user, pw)
        messagebox.showinfo("Saved ✓", "Password saved.\n(Only a SHA-256 hash is stored — never the plaintext.)")
        self.status("💾 Saved to vault.")

    def _history(self):
        user = self.username_var.get().strip()
        if not user:
            messagebox.showinfo("Vault history", "Enter a username to see its history.")
            return
        count, last = self.vault.stats(user)
        msg = f"{count} password(s) stored for '{user}'."
        if last:
            msg += f"\nLast saved: {last}"
        messagebox.showinfo("Vault history", msg)

    def status(self, text):
        self.status_lbl.config(text=text)


if __name__ == "__main__":
    App().mainloop()