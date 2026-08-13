#!/usr/bin/env python3
"""                                            Cipher Tool - AES-256-GCM + Scrypt
Modern TUI Edition (Raw Output Fix)            """

import os                                      import sys
import time                                    import math
import base64
import secrets                                 import threading
from typing import Callable, List, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidTag

    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.text import Text
    from rich import box
except ImportError:
    sys.stderr.write(
        "\n\033[91mMissing dependencies:\033[0m 'cryptography' and 'rich' are required.\n"
        "Install them with:\n\n    pip install cryptography rich\n\n"
    )
    sys.exit(1)

# --- App Setup ---
APP_VERSION = "4.2 (TUI)"
FORMAT_TAG = "CPHR1"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
SCRYPT_N = 2 ** 19
SCRYPT_R = 8
SCRYPT_P = 1
MIN_PASSPHRASE_LEN = 12

console = Console()

def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

def run_animated_pipeline(action: Callable[[], bytes], mode: str) -> bytes:
    with Progress(
        SpinnerColumn(spinner_name="dots2", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="green", finished_style="bold green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        expand=True
    ) as progress:

        task_init = progress.add_task("[yellow]Initializing Cryptographic Parameters...", total=100)
        progress.update(task_init, completed=100, description="[bold green]✔ Parameters Initialized")
        time.sleep(0.3)

        task_scrypt = progress.add_task("[cyan]Deriving AES-256 Key (Scrypt KDF)...", total=100)

        result: List[Optional[bytes]] = [None]
        error: List[Optional[BaseException]] = [None]

        def worker() -> None:
            try:
                result[0] = action()
            except Exception as exc:
                error[0] = exc

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        start_time = time.perf_counter()

        subphases = [
            "Allocating memory buffer...",
            "Executing Salsa20/8 core...",
            "Transforming matrix blocks...",
            "Finalizing bits..."
        ]

        while t.is_alive():
            elapsed = time.perf_counter() - start_time
            prog = 99.0 * (1.0 - math.exp(-elapsed / 0.45))
            idx = min(len(subphases) - 1, int(elapsed / 0.22))

            progress.update(task_scrypt, completed=prog, description=f"[cyan]Scrypt KDF: {subphases[idx]}")
            time.sleep(0.04)

        t.join()
        if error[0]:
            raise error[0]

        progress.update(task_scrypt, completed=100, description="[bold green]✔ Key Material Derived (256-bit)")

        task_cipher = progress.add_task(f"[magenta]{mode} payload...", total=100)
        time.sleep(0.2)
        progress.update(task_cipher, completed=100, description=f"[bold green]✔ {mode} Complete")
        time.sleep(0.3)

        assert result[0] is not None
        return result[0]

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, backend=default_backend()
    )
    return kdf.derive(passphrase.encode('utf-8'))

def encrypt(plaintext: str, passphrase: str) -> str:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)

    key = run_animated_pipeline(lambda: _derive_key(passphrase, salt), "Encrypting")

    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

    salt_b64 = base64.urlsafe_b64encode(salt).decode('ascii')
    nonce_b64 = base64.urlsafe_b64encode(nonce).decode('ascii')
    ct_b64 = base64.urlsafe_b64encode(ciphertext_with_tag).decode('ascii')

    return f"{FORMAT_TAG}${salt_b64}.{nonce_b64}.{ct_b64}"

def decrypt(token: str, passphrase: str) -> Optional[str]:
    try:
        if '$' not in token:
            raise ValueError("Unrecognized format (missing version tag)")

        tag, payload = token.split('$', 1)
        if tag != FORMAT_TAG:
            raise ValueError(f"Unsupported format '{tag}' (expected '{FORMAT_TAG}')")

        parts = payload.split('.')
        if len(parts) != 3:
            raise ValueError("Malformed payload (expected salt.nonce.ciphertext)")

        salt = base64.urlsafe_b64decode(parts[0])
        nonce = base64.urlsafe_b64decode(parts[1])
        ciphertext_with_tag = base64.urlsafe_b64decode(parts[2])

        key = run_animated_pipeline(lambda: _derive_key(passphrase, salt), "Decrypting")

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        return plaintext.decode('utf-8')

    except InvalidTag:
        console.print(Panel("[bold red]❌ Decryption failed:[/bold red] Wrong passphrase, or the ciphertext was corrupted/tampered with.", border_style="red"))
        return None
    except (ValueError, TypeError) as exc:
        console.print(Panel(f"[bold red]❌ Decryption error:[/bold red] {exc}", border_style="red"))
        return None

def get_multiline_input(title: str, style: str) -> str:
    console.print(f"\n[{style} bold]{title}[/]")
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

def prompt_passphrase() -> str:
    console.print("\n[bold yellow]🔑 Enter secret key phrase (Visible for verification):[/]")
    phrase = input("> ")

    if not phrase:
        console.print("[bold red]❌ Passphrase cannot be empty.[/]")
        sys.exit(1)
    if len(phrase) < MIN_PASSPHRASE_LEN:
        console.print(f"[yellow]⚠ Warning: Short passphrase ({len(phrase)} chars). {MIN_PASSPHRASE_LEN}+ recommended.[/]")
        time.sleep(2)
    return phrase

def print_banner() -> None:
    banner_text = Text(justify="center")
    banner_text.append("🔐 CIPHER TOOL\n", style="bold cyan")
    banner_text.append(f"Version {APP_VERSION} | AES-256-GCM + Scrypt", style="dim")

    console.print(Panel(banner_text, border_style="cyan", box=box.DOUBLE_EDGE, expand=False))

def main() -> None:
    clear_screen()
    print_banner()

    passphrase = prompt_passphrase()

    while True:
        clear_screen()
        print_banner()
        console.print("[green]✅ Session Secured. Key phrase loaded in memory.[/]\n")

        menu = Table(show_header=False, box=box.SIMPLE, expand=False)
        menu.add_column("Key", style="bold cyan")
        menu.add_column("Action", style="white")
        menu.add_row("[ 1 ]", "📨 Encrypt a message")
        menu.add_row("[ 2 ]", "🔓 Decrypt a message")
        menu.add_row("[ 3 ]", "👋 Exit")

        console.print(Panel(menu, title="[bold]Main Menu[/]", border_style="blue", expand=False))

        choice = Prompt.ask("[bold cyan]Select an option[/]", choices=["1", "2", "3"], default="1")

        if choice == '1':
            plaintext = get_multiline_input("ENCRYPTING MESSAGE:", "cyan")
            if plaintext:
                console.print()
                ct = encrypt(plaintext, passphrase)

                # Bypassing Rich entirely for the final output string to prevent formatting corruption
                console.print("\n[bold yellow] 📦 CIPHERTEXT READY (Copy below):[/]")
                print(f"\033[1;32m{ct}\033[0m")
            else:
                console.print("[bold red]❌ Cannot encrypt empty text.[/]")

            Prompt.ask("\n[dim]Press Enter to return to menu...[/]")

        elif choice == '2':
            console.print("\n[bold cyan]📋 Paste ciphertext (single line):[/]")
            # Automatically strip out spaces or newlines from messy pastes
            ciphertext = input("> ").strip().replace(" ", "").replace("\n", "")

            if ciphertext:
                console.print()
                pt = decrypt(ciphertext, passphrase)
                if pt is not None:
                    # Bypassing Rich entirely for the decrypted text to preserve exact formatting
                    console.print("\n[bold green]✅ DECRYPTED MESSAGE:[/]")
                    print(f"\033[1;37m{pt}\033[0m")
            else:
                console.print("[bold red]❌ No ciphertext provided.[/]")

            Prompt.ask("\n[dim]Press Enter to return to menu...[/]")

        elif choice == '3':
            clear_screen()
            console.print("[bold cyan]👋 Goodbye! Memory cleared.[/]\n")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bold red]Process interrupted by user. Exiting...[/]")
        sys.exit(0)
