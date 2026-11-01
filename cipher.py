#!/usr/bin/env python3
"""
Premium Cipher - Termux Edition
AES-256-GCM + Scrypt (512MB, native-grade) | Premium Gold TUI
Developed by Ibrahim Khaled
"""

import os
import sys
import time
import base64
import secrets
import threading
import getpass
import hashlib
import hmac
import unicodedata
import subprocess
from typing import Callable, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.exceptions import InvalidTag

    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.prompt import Prompt
    from rich import box
except ImportError:
    sys.stderr.write(
        "\nMissing dependencies. Run:\n\n    pip install cryptography rich\n\n"
    )
    sys.exit(1)

# --- App Setup ---
APP_VERSION = "5.0 (Termux Premium)"
FORMAT_TAG = "CPHR3"
SALT_LEN = 16
NONCE_LEN = 12
SCRYPT_N = 2 ** 19      # 512MB memory-hard, same as Termux Python original
SCRYPT_R = 8
SCRYPT_P = 1
MIN_RECOMMENDED = 12
GOLD = "#FFD700"

MESSAGES = [
    "Allocating secure memory...",
    "Deriving 256-bit AES key...",
    "Executing memory-hard Scrypt...",
    "Finalizing cryptographic payload...",
]

console = Console()


class CryptoError(Exception):
    pass


# --- Helpers ---
def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii')


def _ub64(data: str) -> bytes:
    padded = data + '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def _mac_payload(tag: str, salt: bytes, nonce: bytes, ct: bytes) -> bytes:
    return tag.encode('utf-8') + b'\x00' + salt + b'\x00' + nonce + b'\x00' + ct


def _scrypt(pass_bytes: bytes, salt: bytes, length: int) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(pass_bytes)


def copy_to_clipboard(text: str) -> bool:
    """Best-effort copy using Termux API. Returns False if unavailable."""
    try:
        subprocess.run(
            ["termux-clipboard-set"],
            input=text.encode('utf-8'),
            check=True,
            timeout=5,
        )
        return True
    except Exception:
        return False


# --- Premium animated pipeline (NO TIMEOUT) ---
def _pipeline_renderable(mode: str, msg: str, elapsed: float) -> Panel:
    lock = "🔐" if int(elapsed * 2) % 2 == 0 else "🔒"
    text = Text()
    text.append(f"{lock} ", style="bold")
    text.append(f"{mode}ing Securely...\n", style=f"bold {GOLD}")
    text.append(f"› {msg}\n", style="dim")
    text.append(f"› elapsed {elapsed:.1f}s — no timeout, take your time", style="dim italic")
    return Panel(text, border_style=GOLD, box=box.DOUBLE_EDGE, expand=False)


def run_premium_pipeline(action: Callable[[], bytes], mode: str) -> bytes:
    result = [None]
    error = [None]

    def worker() -> None:
        try:
            result[0] = action()
        except Exception as exc:
            error[0] = exc

    t = threading.Thread(target=worker, daemon=True)
    start = time.perf_counter()
    t.start()

    with Live(console=console, refresh_per_second=8) as live:
        while t.is_alive():
            elapsed = time.perf_counter() - start
            msg = MESSAGES[int(elapsed // 2.5) % len(MESSAGES)]
            live.update(_pipeline_renderable(mode, msg, elapsed))
            time.sleep(0.12)

    if error[0] is not None:
        raise error[0]
    assert result[0] is not None
    return result[0]


# --- Crypto Engine (identical to the Android app) ---
def encrypt(plaintext: str, passphrase: str) -> str:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    pass_bytes = unicodedata.normalize("NFKC", passphrase).encode('utf-8')

    material = run_premium_pipeline(lambda: _scrypt(pass_bytes, salt, 64), "Encrypt")
    enc_key, ver_key = material[:32], material[32:]

    ct = AESGCM(enc_key).encrypt(nonce, plaintext.encode('utf-8'), FORMAT_TAG.encode('utf-8'))
    verifier = hmac.new(ver_key, _mac_payload(FORMAT_TAG, salt, nonce, ct), hashlib.sha256).digest()

    return f"{FORMAT_TAG}${_b64(salt)}.{_b64(nonce)}.{_b64(ct)}.{_b64(verifier)}"


def decrypt(token: str, passphrase: str) -> str:
    cleaned = "".join(token.split())
    if '$' not in cleaned:
        raise CryptoError("Malformed token.")

    tag, payload = cleaned.split('$', 1)
    parts = payload.split('.')

    try:
        if tag == FORMAT_TAG:
            if len(parts) != 4:
                raise CryptoError("Malformed CPHR3 payload.")
            salt, nonce, ct, verifier = (_ub64(parts[i]) for i in range(4))
            pass_bytes = unicodedata.normalize("NFKC", passphrase).encode('utf-8')

            material = run_premium_pipeline(lambda: _scrypt(pass_bytes, salt, 64), "Decrypt")
            enc_key, ver_key = material[:32], material[32:]

            expected = hmac.new(ver_key, _mac_payload(FORMAT_TAG, salt, nonce, ct), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, verifier):
                raise CryptoError("Invalid passphrase or corrupted data.")

            pt = AESGCM(enc_key).decrypt(nonce, ct, FORMAT_TAG.encode('utf-8'))
            return pt.decode('utf-8')

        elif tag == "CPHR2":
            if len(parts) != 4:
                raise CryptoError("Malformed CPHR2 payload.")
            salt, nonce, ct = (_ub64(parts[i]) for i in range(3))
            # Legacy weak verifier (parts[3]) intentionally ignored.
            pass_bytes = passphrase.encode('utf-8')
            key = run_premium_pipeline(lambda: _scrypt(pass_bytes, salt, 32), "Decrypt")
            pt = AESGCM(key).decrypt(nonce, ct, None)
            return pt.decode('utf-8')

        elif tag == "CPHR1":
            if len(parts) != 3:
                raise CryptoError("Malformed CPHR1 payload.")
            salt, nonce, ct = (_ub64(parts[i]) for i in range(3))
            pass_bytes = passphrase.encode('utf-8')
            key = run_premium_pipeline(lambda: _scrypt(pass_bytes, salt, 32), "Decrypt")
            pt = AESGCM(key).decrypt(nonce, ct, None)
            return pt.decode('utf-8')

        else:
            raise CryptoError(f"Unsupported format: {tag}")

    except InvalidTag:
        raise CryptoError("Invalid passphrase or corrupted data.")
    except UnicodeDecodeError:
        raise CryptoError("Invalid passphrase or corrupted data.")
    except ValueError:
        raise CryptoError("Malformed token.")


# --- UI ---
def print_banner() -> None:
    t = Text(justify="center")
    t.append("🔐 PREMIUM CIPHER 🔐\n", style=f"bold {GOLD}")
    t.append(f"Version {APP_VERSION} | AES-256-GCM • Scrypt 512MB\n", style="dim")
    t.append("Developed by Ibrahim Khaled", style="dim italic")
    console.print(Panel(t, border_style=GOLD, box=box.DOUBLE_EDGE, expand=False))


def prompt_passphrase(confirm: bool = False) -> str:
    while True:
        console.print(f"\n[bold {GOLD}]🔑 Enter master passphrase (hidden):[/]")
        phrase = getpass.getpass("> ")

        if not phrase:
            console.print("[bold red]❌ Passphrase cannot be empty.[/]")
            continue

        normalized = unicodedata.normalize("NFKC", phrase)
        if len(normalized) < MIN_RECOMMENDED:
            console.print(f"[yellow]⚠ Warning: short passphrase. {MIN_RECOMMENDED}+ characters recommended.[/]")

        if confirm:
            console.print(f"[bold {GOLD}]🔑 Confirm passphrase:[/]")
            confirm_phrase = getpass.getpass("> ")
            a = unicodedata.normalize("NFKC", phrase).encode('utf-8')
            b = unicodedata.normalize("NFKC", confirm_phrase).encode('utf-8')
            if not hmac.compare_digest(a, b):
                console.print("[bold red]❌ Passphrases do not match. Try again.[/]")
                continue

        return phrase


def get_multiline_input(title: str) -> str:
    console.print(f"\n[bold {GOLD}]{title}[/]")
    console.print("[dim]Type your message. Press Enter twice on a blank line to finish (or Ctrl+D).[/]")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == "" and lines and lines[-1] == "":
            break
        lines.append(line)
    if lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


def main() -> None:
    clear_screen()
    print_banner()
    passphrase = prompt_passphrase(confirm=True)

    while True:
        clear_screen()
        print_banner()
        console.print("[green]✅ Session unlocked. Works with all languages and emoji.[/]\n")

        menu = Table(show_header=False, box=box.SIMPLE, expand=False)
        menu.add_column("Key", style=f"bold {GOLD}")
        menu.add_column("Action", style="white")
        menu.add_row("[ 1 ]", "📨 Encrypt a message")
        menu.add_row("[ 2 ]", "🔓 Decrypt a message")
        menu.add_row("[ 3 ]", "🔄 Change passphrase")
        menu.add_row("[ 4 ]", "👋 Exit")
        console.print(Panel(menu, title="[bold]Main Menu[/]", border_style=GOLD, box=box.DOUBLE_EDGE, expand=False))

        choice = Prompt.ask("[bold #FFD700]Select an option[/]", choices=["1", "2", "3", "4"], default="1")

        if choice == '1':
            plaintext = get_multiline_input("ENCRYPTING MESSAGE:")
            if plaintext:
                console.print()
                try:
                    token = encrypt(plaintext, passphrase)
                    console.print(f"\n[bold {GOLD}]📦 CIPHERTEXT READY:[/]")
                    print(token)  # raw line, no ANSI, safe to copy
                    if copy_to_clipboard(token):
                        console.print("[dim]📋 Copied to clipboard.[/]")
                except CryptoError as e:
                    console.print(f"[bold red]❌ {e}[/]")
            else:
                console.print("[bold red]❌ Cannot encrypt empty text.[/]")
            Prompt.ask("\n[dim]Press Enter to return to menu...[/]")

        elif choice == '2':
            console.print(f"\n[bold {GOLD}]📋 Paste ciphertext (CPHR3 / CPHR2 / CPHR1):[/]")
            token = input("> ")
            if token.strip():
                console.print()
                try:
                    pt = decrypt(token, passphrase)
                    console.print(f"\n[bold green]✅ DECRYPTED MESSAGE:[/]")
                    print(pt)  # raw line, exact text
                    if copy_to_clipboard(pt):
                        console.print("[dim]📋 Copied to clipboard.[/]")
                except CryptoError as e:
                    console.print(f"[bold red]❌ {e}[/]")
            else:
                console.print("[bold red]❌ No ciphertext provided.[/]")
            Prompt.ask("\n[dim]Press Enter to return to menu...[/]")

        elif choice == '3':
            passphrase = prompt_passphrase(confirm=True)
            console.print("[bold green]✅ Passphrase updated for this session.[/]")
            Prompt.ask("\n[dim]Press Enter to return to menu...[/]")

        elif choice == '4':
            confirm = Prompt.ask("[yellow]⚠ Are you sure you want to exit?[/]", choices=["y", "n"], default="n")
            if confirm.lower() == 'y':
                clear_screen()
                console.print(f"[bold {GOLD}]👋 Goodbye! — Developed by Ibrahim Khaled[/]\n")
                break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bold red]Process interrupted by user. Exiting...[/]")
        sys.exit(0)
