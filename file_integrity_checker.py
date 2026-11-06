#!/usr/bin/env python3
"""
File Integrity Checker 📁
=========================
Monitors files and detects if they have been modified using hashing.
Author: hemanathan115
GitHub: https://github.com/hemanathan115
"""

import hashlib
import json
import os
import sys
import argparse
import time
import tempfile
from datetime import datetime
from pathlib import Path
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

HASH_DB_FILE = "hash_database.json"
SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]
DEFAULT_ALGORITHM = "sha256"


# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║         📁  FILE INTEGRITY CHECKER  📁               ║
║      Detect File Tampering Using Hashing             ║
║      GitHub: github.com/hemanathan115               ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


# ─────────────────────────────────────────────
#  HASHING
# ─────────────────────────────────────────────
def compute_hash(filepath: str, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Compute the hash of a file using the specified algorithm."""
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        return None
    except PermissionError:
        print(f"{Fore.RED}[ERROR] Permission denied: {filepath}{Style.RESET_ALL}")
        return None


# ─────────────────────────────────────────────
#  DATABASE HELPERS
# ─────────────────────────────────────────────
def load_database(db_path: str) -> dict:
    """Load the hash database from a JSON file."""
    if os.path.exists(db_path):
        with open(db_path, "r") as f:
            return json.load(f)
    return {}


def save_database(db: dict, db_path: str):
    """Atomically replace the hash database without following a target symlink."""
    target = Path(db_path)
    parent = target.parent if str(target.parent) else Path(".")
    fd, temp_path = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=4)
            f.flush()
            os.fsync(f.fileno())
        # os.replace replaces a symlink itself rather than writing through it.
        os.replace(temp_path, target)
    except Exception:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise


# ─────────────────────────────────────────────
#  GENERATE HASHES (Baseline Snapshot)
# ─────────────────────────────────────────────
def generate_hashes(targets: list, algorithm: str, db_path: str, recursive: bool):
    """Generate and store hashes for all target files/directories."""
    db = load_database(db_path)
    count = 0

    files = collect_files(targets, recursive)

    print(f"\n{Fore.YELLOW}[*] Generating hashes using {algorithm.upper()}...{Style.RESET_ALL}\n")

    for filepath in files:
        abs_path = str(Path(filepath).resolve())
        file_hash = compute_hash(abs_path, algorithm)
        if file_hash:
            db[abs_path] = {
                "hash": file_hash,
                "algorithm": algorithm,
                "last_checked": datetime.now().isoformat(),
                "size": os.path.getsize(abs_path),
            }
            print(f"  {Fore.GREEN}[+] {abs_path}{Style.RESET_ALL}")
            print(f"      Hash ({algorithm}): {file_hash}")
            count += 1

    save_database(db, db_path)
    print(f"\n{Fore.CYAN}[✓] Baseline created for {count} file(s). Saved to '{db_path}'.{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────
#  VERIFY HASHES (Tamper Detection)
# ─────────────────────────────────────────────
def verify_hashes(targets: list, db_path: str, recursive: bool):
    """Verify files against stored hashes and report any changes."""
    db = load_database(db_path)

    if not db:
        print(f"{Fore.RED}[!] No hash database found. Run --generate first.{Style.RESET_ALL}")
        sys.exit(1)

    files = collect_files(targets, recursive) if targets else list(db.keys())

    print(f"\n{Fore.YELLOW}[*] Verifying file integrity...{Style.RESET_ALL}\n")

    ok_count = 0
    tampered_count = 0
    missing_count = 0
    new_count = 0

    for filepath in files:
        abs_path = str(Path(filepath).resolve()) if targets else filepath

        if abs_path not in db:
            print(f"  {Fore.BLUE}[NEW]     {abs_path}{Style.RESET_ALL}  ← Not in baseline")
            new_count += 1
            continue

        record = db[abs_path]
        algorithm = record["algorithm"]
        stored_hash = record["hash"]

        current_hash = compute_hash(abs_path, algorithm)

        if current_hash is None:
            print(f"  {Fore.RED}[MISSING] {abs_path}{Style.RESET_ALL}  ← File not found!")
            missing_count += 1
        elif current_hash == stored_hash:
            print(f"  {Fore.GREEN}[OK]      {abs_path}{Style.RESET_ALL}")
            ok_count += 1
        else:
            print(f"  {Fore.RED}[TAMPERED]{Style.RESET_ALL} {abs_path}")
            print(f"            Stored : {stored_hash}")
            print(f"            Current: {current_hash}")
            tampered_count += 1

    # Summary
    print(f"""
{Fore.CYAN}══════════════════════ SUMMARY ══════════════════════{Style.RESET_ALL}
  {Fore.GREEN}✓ Intact   : {ok_count}{Style.RESET_ALL}
  {Fore.RED}✗ Tampered : {tampered_count}{Style.RESET_ALL}
  {Fore.RED}⚠ Missing  : {missing_count}{Style.RESET_ALL}
  {Fore.BLUE}+ New      : {new_count}{Style.RESET_ALL}
{Fore.CYAN}═════════════════════════════════════════════════════{Style.RESET_ALL}
""")

    if tampered_count > 0 or missing_count > 0:
        sys.exit(2)  # Non-zero exit for scripting / CI use


# ─────────────────────────────────────────────
#  LIST DATABASE
# ─────────────────────────────────────────────
def list_database(db_path: str):
    """Display all entries in the hash database."""
    db = load_database(db_path)
    if not db:
        print(f"{Fore.YELLOW}[!] Database is empty or not found.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[*] Hash Database: {db_path}{Style.RESET_ALL}\n")
    for i, (filepath, record) in enumerate(db.items(), 1):
        print(f"  {Fore.YELLOW}{i}. {filepath}{Style.RESET_ALL}")
        print(f"     Algorithm : {record['algorithm'].upper()}")
        print(f"     Hash      : {record['hash']}")
        print(f"     Size      : {record.get('size', 'N/A')} bytes")
        print(f"     Checked   : {record.get('last_checked', 'N/A')}")
        print()


# ─────────────────────────────────────────────
#  MONITOR MODE (Continuous Watching)
# ─────────────────────────────────────────────
def monitor_mode(targets: list, db_path: str, interval: int, recursive: bool):
    """Continuously monitor files and alert on changes."""
    print(f"\n{Fore.CYAN}[*] Monitor mode active. Checking every {interval}s. Press Ctrl+C to stop.{Style.RESET_ALL}\n")
    try:
        while True:
            print(f"{Fore.YELLOW}[{datetime.now().strftime('%H:%M:%S')}] Running integrity check...{Style.RESET_ALL}")
            verify_hashes(targets, db_path, recursive)
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}[*] Monitoring stopped.{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  REMOVE ENTRY
# ─────────────────────────────────────────────
def remove_entry(filepath: str, db_path: str):
    """Remove a file entry from the hash database."""
    db = load_database(db_path)
    abs_path = str(Path(filepath).resolve())
    if abs_path in db:
        del db[abs_path]
        save_database(db, db_path)
        print(f"{Fore.GREEN}[✓] Removed: {abs_path}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] Entry not found: {abs_path}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  FILE COLLECTOR
# ─────────────────────────────────────────────
def collect_files(targets: list, recursive: bool) -> list:
    """Collect all files from given paths (files or directories)."""
    files = []
    for target in targets:
        p = Path(target)
        if p.is_file():
            files.append(str(p))
        elif p.is_dir():
            pattern = "**/*" if recursive else "*"
            for f in p.glob(pattern):
                if f.is_file():
                    files.append(str(f))
        else:
            print(f"{Fore.RED}[!] Not found: {target}{Style.RESET_ALL}")
    return files


# ─────────────────────────────────────────────
#  CLI ARGUMENT PARSER
# ─────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="file_integrity_checker",
        description="📁 File Integrity Checker — Detect file tampering using hashing",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  Generate baseline:
    python file_integrity_checker.py --generate file.txt mydir/

  Verify integrity:
    python file_integrity_checker.py --verify file.txt

  Verify all tracked files:
    python file_integrity_checker.py --verify

  Monitor continuously:
    python file_integrity_checker.py --monitor --interval 30

  List database:
    python file_integrity_checker.py --list

  Remove entry:
    python file_integrity_checker.py --remove file.txt

  Use SHA512 algorithm:
    python file_integrity_checker.py --generate file.txt --algorithm sha512
""",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate", "-g", nargs="+", metavar="PATH",
                       help="Generate/update hashes for file(s) or directory(ies)")
    group.add_argument("--verify", "-v", nargs="*", metavar="PATH",
                       help="Verify integrity of file(s). If no PATH given, checks all in DB.")
    group.add_argument("--monitor", "-m", action="store_true",
                       help="Continuously monitor files for changes")
    group.add_argument("--list", "-l", action="store_true",
                       help="List all entries in the hash database")
    group.add_argument("--remove", "-r", metavar="PATH",
                       help="Remove a file entry from the database")

    parser.add_argument("--algorithm", "-a", choices=SUPPORTED_ALGORITHMS,
                        default=DEFAULT_ALGORITHM,
                        help=f"Hash algorithm to use (default: {DEFAULT_ALGORITHM})")
    parser.add_argument("--db", default=HASH_DB_FILE,
                        help=f"Path to hash database file (default: {HASH_DB_FILE})")
    parser.add_argument("--recursive", "-R", action="store_true",
                        help="Recursively scan directories")
    parser.add_argument("--interval", "-i", type=int, default=60,
                        help="Monitor check interval in seconds (default: 60)")

    return parser


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    if args.generate:
        generate_hashes(args.generate, args.algorithm, args.db, args.recursive)

    elif args.verify is not None:
        verify_hashes(args.verify if args.verify else [], args.db, args.recursive)

    elif args.monitor:
        verify_hashes([], args.db, args.recursive)
        monitor_mode([], args.db, args.interval, args.recursive)

    elif args.list:
        list_database(args.db)

    elif args.remove:
        remove_entry(args.remove, args.db)


if __name__ == "__main__":
    main()
