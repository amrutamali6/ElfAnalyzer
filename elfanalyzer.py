# =============================================================
#  ELF Analyzer — Hash, Suspicious Imports & JSON Report
# =============================================================

# ── Imports ───────────────────────────────────────────────────
import hashlib
import re
import json
import os
from datetime import datetime
from ElfAnalyzer import *


# ── Constants ─────────────────────────────────────────────────

# Benign binaries
#ELF_PATH = "/home/amruta/benign_binaries/nc"  # Change this to your ELF binary path
#ELF_PATH = "/home/amruta/benign_binaries/cat"
#ELF_PATH = "/home/amruta/benign_binaries/ls"
#ELF_PATH = "/home/amruta/benign_binaries/grep"
#ELF_PATH = "/home/amruta/benign_binaries/echo"
#ELF_PATH = "/home/amruta/benign_binaries/ngrok"

#ELF_PATH = "/home/amruta/benign_binaries/x86__64__lsb__unix-system-v__clang-3.8.0__O0__no-obf__unstripped__wget-1.16__wget"  
#ELF_PATH = "/home/amruta/benign_binaries/x86__64__lsb__unix-system-v__clang-3.8.0__O1__no-obf__unstripped__acpid-2.0.31__sock.o"  
#ELF_PATH = "/home/amruta/benign_binaries/x86__64__lsb__unix-system-v__clang-3.8.0__O1__no-obf__unstripped__coreutils-8.30__sha1sum"  
#ELF_PATH = "/home/amruta/benign_binaries/x86__64__lsb__unix-system-v__clang-3.8.0__O1__no-obf__unstripped__util-linux-2.33__hexdump"  

#ELF_PATH = "/home/amruta/benign_binaries/netcat-openbsd_1.229-1_amd64.deb"
#ELF_PATH = "/home/amruta/benign_binaries/ngrok-stable-linux-amd64.zip"
#ELF_PATH = "/home/amruta/benign_binaries/sendip_2.6-1_amd64.deb"
#ELF_PATH = "/home/amruta/benign_binaries/tcpdump_4.99.6-2_amd64.deb"

# Malicous binaries
#ELF_PATH = "/home/amruta/malicious_binaries/1708621d7ed75e711d925cb96436fa5a5403c29c5b71b5159170114c532962b5.zip"
#ELF_PATH = "/home/amruta/malicious_binaries/8d385e7b91c3cdd6c17a071f238602d4837d5deed5f213f93d02c15674367a10.zip" 
#ELF_PATH = "/home/amruta/malicious_binaries/4771b1cb3f6e33666f523f9c46b2a3d3ae83f616531376bff964be7420d7f64c.zip" 
#ELF_PATH = "/home/amruta/malicious_binaries/646ed823a06ae53ac9c9117f68520916e67468bfa0ef6412c35682743cab5819.zip"  
#ELF_PATH = "/home/amruta/malicious_binaries/76f9f2ceca29648448664c901a5de2432ed044f2056aa32aeaa3791cb5f9c4b5.zip"  
#ELF_PATH = "/home/amruta/malicious_binaries/6a6adc9d0b8be0da006c11564827258d086da534da452229865314446f36f563.zip"  
ELF_PATH = "/home/amruta/malicious_binaries/3b5d8ab8a0e8335bf542bc9e7f7a79360b541c920263de8fa2deb6ea1def361d.zip"  


SUSPICIOUS_IMPORTS = {
    "Shell Execution": [
        "system", "execve", "execl", "execlp", "execvp", "execvpe",
        "popen", "posix_spawn", "shellcode", "shell"
    ],
    "Network": [
        "socket", "connect", "bind", "listen", "accept", "recv", "send",
        "sendto", "recvfrom", "gethostbyname", "getaddrinfo", "inet_addr",
        "curl", "wget", "http", "ftp", "ncat", "netcat"
    ],
    "File Manipulation": [
        "unlink", "remove", "rename", "chmod", "chown", "truncate",
        "ftruncate", "symlink", "link", "mknod", "mkdir", "rmdir"
    ],
    "Memory Manipulation": [
        "mmap", "mprotect", "munmap", "ptrace", "process_vm_readv",
        "process_vm_writev", "memcpy", "memmove", "memset"
    ],
    "Privilege Escalation": [
        "setuid", "setgid", "setreuid", "setregid", "setresuid",
        "setresgid", "capset", "prctl", "sudo", "su"
    ],
    "Obfuscation / Injection": [
        "dlopen", "dlsym", "dlclose", "LD_PRELOAD", "inject",
        "hook", "patch", "decrypt", "encode", "base64", "xor"
    ],
    "Process Manipulation": [
        "fork", "clone", "kill", "signal", "raise", "abort",
        "waitpid", "wait4", "ptrace"
    ],
    "Keylogging / Spying": [
        "getchar", "fgetc", "read", "inotify", "fanotify",
        "keylog", "intercept", "sniff", "capture"
    ],
    "Persistence": [
        "crontab", "at", "init", "systemd", "rc.local",
        "bashrc", "profile", "autorun", "startup"
    ],
    "Crypto / Ransomware": [
        "EVP_EncryptInit", "EVP_DecryptInit", "AES", "RSA",
        "encrypt", "decrypt", "ransom", "locker"
    ],
}


# ── Functions ─────────────────────────────────────────────────

def compute_hashes(filepath):
    """Compute MD5, SHA1, SHA256, SHA512 hashes of a file."""
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    return {
        "MD5"    : md5.hexdigest(),
        "SHA1"   : sha1.hexdigest(),
        "SHA256" : sha256.hexdigest(),
        "SHA512" : sha512.hexdigest(),
    }


def parse_elf(filepath):
    """Parse an ELF binary and return all components."""
    with open(filepath, "rb") as f:
        (
            elfindent,
            elf_headers,
            programs_headers,
            elf_sections,
            symbols_tables,
            comments,
            note_sections,
            notes,
            dynamics,
            sections
        ) = parse_elffile(f)

    return (
        elfindent, elf_headers, programs_headers, elf_sections,
        symbols_tables, comments, note_sections, notes, dynamics, sections
    )


def extract_suspicious_imports(filepath):
    """Extract printable strings from binary and flag suspicious ones by category."""
    found = {category: [] for category in SUSPICIOUS_IMPORTS}

    with open(filepath, "rb") as f:
        raw = f.read()

    strings_found = re.findall(rb'[ -~]{4,}', raw)
    decoded = [s.decode("ascii", errors="ignore") for s in strings_found]

    for string in decoded:
        for category, keywords in SUSPICIOUS_IMPORTS.items():
            for keyword in keywords:
                if re.search(rf'(?i)(^|[^a-z0-9_]){re.escape(keyword)}([^a-z0-9_]|$)', string):
                    if string not in found[category]:
                        found[category].append(string)

    return found


def export_json(filepath, hashes, suspicious):
    """Export hashes and suspicious imports to a JSON report file."""
    total_hits = sum(len(v) for v in suspicious.values())

    report = {
        "report_generated"  : datetime.now().isoformat(),
        "file"              : os.path.abspath(filepath),
        "filename"          : os.path.basename(filepath),
        "hashes": {
            "MD5"    : hashes["MD5"],
            "SHA1"   : hashes["SHA1"],
            "SHA256" : hashes["SHA256"],
            "SHA512" : hashes["SHA512"],
        },
        "suspicious_imports": {
            "total_hits"        : total_hits,
            "categories_flagged": sum(1 for v in suspicious.values() if v),
            "matches"           : {
                category: matches
                for category, matches in suspicious.items()
                if matches
            }
        }
    }

    output_path = os.path.splitext(filepath)[0] + "_analysis.json"
    with open(output_path, "w") as f:
        json.dump(report, f, indent=4)

    return output_path, report


def safe_repr(obj):
    """
    Safely convert an ElfAnalyzer object to a readable string.
    Works around the TypeError: can only concatenate str (not 'Field') to str
    bug present in ElfAnalyzer.py's __str__ method on Python 3.13+.
    Falls back to extracting __annotations__ manually.
    """
    try:
        return str(obj)
    except TypeError:
        pass

    # Fallback: manually read annotated fields
    try:
        lines = []
        for attr in obj.__annotations__:
            try:
                val = getattr(obj, attr, "?")
                # If the value itself is also a broken object, recurse
                try:
                    str(val)
                except TypeError:
                    val = safe_repr(val)
                lines.append(f"  {attr} = {val}")
            except Exception:
                lines.append(f"  {attr} = <unreadable>")
        return "\n".join(lines) if lines else repr(obj)
    except Exception:
        return repr(obj)


def safe_print_list(items):
    """Safely print a list of ElfAnalyzer objects."""
    if not items:
        print("  (empty)")
        return
    for item in items:
        print(safe_repr(item))
        print()


def print_section(title, content):
    """Print a labeled section divider with content, safely handling broken __str__."""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)
    if isinstance(content, list):
        safe_print_list(content)
    else:
        print(safe_repr(content))


def display_hashes(hashes):
    """Print hash values to console."""
    print("=" * 60)
    print("FILE HASH VALUES")
    print("=" * 60)
    for algo, value in hashes.items():
        print(f"{algo:<10}: {value}")


def display_suspicious_imports(suspicious):
    """Print suspicious import findings to console."""
    total_hits = sum(len(v) for v in suspicious.values())

    print("\n" + "=" * 60)
    print("SUSPICIOUS IMPORT STRINGS")
    print("=" * 60)

    if total_hits == 0:
        print("[*] No suspicious imports detected.")
    else:
        print(f"[!] {total_hits} hit(s) across {sum(1 for v in suspicious.values() if v)} categories\n")
        for category, matches in suspicious.items():
            if matches:
                print(f"  ▶ {category} ({len(matches)} match(es)):")
                for m in matches:
                    print(f"      - {m}")
                print()

    return total_hits


def display_elf_components(elfindent, elf_headers, programs_headers,
                           symbols_tables, dynamics, sections, comments, notes):
    """Print all parsed ELF components to console."""
    print_section("ELF IDENT",       elfindent)
    print_section("ELF HEADERS",     elf_headers)
    print_section("PROGRAM HEADERS", programs_headers)
    print_section("SYMBOL TABLES",   symbols_tables)
    print_section("DYNAMICS",        dynamics)
    print_section("SECTIONS",        sections)
    print_section("COMMENTS",        comments)
    print_section("NOTES",           notes)


def display_summary(filepath, hashes, suspicious, total_hits):
    """Print final analysis summary."""
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"File    : {filepath}")
    for algo, value in hashes.items():
        print(f"{algo:<10}: {value}")
    print(f"\nSuspicious Imports: {total_hits} hit(s) found")
    for category, matches in suspicious.items():
        if matches:
            print(f"  ▶ {category}: {len(matches)} match(es)")


# ── Main Execution ────────────────────────────────────────────

# 1. Compute hashes
hashes = compute_hashes(ELF_PATH)
display_hashes(hashes)

# 2. Extract suspicious imports
suspicious = extract_suspicious_imports(ELF_PATH)
total_hits = display_suspicious_imports(suspicious)

# 3. Parse ELF file
print("\n" + "=" * 60)
print("PARSING ELF FILE")
print("=" * 60)

(
    elfindent, elf_headers, programs_headers, elf_sections,
    symbols_tables, comments, note_sections, notes, dynamics, sections
) = parse_elf(ELF_PATH)

print(f"[+] ELF file parsed successfully: {ELF_PATH}")

# 4. Display ELF components
display_elf_components(
    elfindent, elf_headers, programs_headers,
    symbols_tables, dynamics, sections, comments, notes
)

# 5. Display summary
display_summary(ELF_PATH, hashes, suspicious, total_hits)

# 6. Export JSON report
print("\n" + "=" * 60)
print("EXPORTING JSON REPORT")
print("=" * 60)

json_path, report = export_json(ELF_PATH, hashes, suspicious)
print(f"[+] JSON report saved to: {json_path}\n")
print(json.dumps(report, indent=4))

# 7. Launch interactive CLI
print("\n[*] Launching ElfAnalyzer CLI...\n")
cli(elfindent, elf_headers, programs_headers, elf_sections,
    symbols_tables, comments, notes, dynamics, sections)
