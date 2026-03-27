# 🔍 ELF Analyzer — Hash, Suspicious Imports & JSON Report

A Python-based security analysis tool for examining **ELF (Executable and Linkable Format)** binaries. This tool helps identify potentially malicious behavior by computing file hashes, extracting suspicious imports, parsing ELF structures, and generating detailed JSON reports.

---

## 🚀 Features

- 🔐 **Multi-Hash Generation**
  - MD5
  - SHA1
  - SHA256
  - SHA512

- 🧠 **Suspicious Import Detection**
  - Categorizes risky strings such as:
    - Shell execution
    - Network activity
    - File manipulation
    - Privilege escalation
    - Obfuscation / injection
    - Persistence mechanisms
    - Crypto / ransomware indicators

- 🧩 **ELF Parsing**
  - Extracts:
    - ELF headers
    - Program headers
    - Sections
    - Symbol tables
    - Dynamic entries
    - Notes & comments

- 📄 **JSON Report Export**
  - Structured output for automation & reporting

- 🖥️ **Interactive CLI**
  - Explore ELF internals dynamically

---

## 📂 Project Structure

```
.
├── analyzer.py        # Main script
├── ElfAnalyzer.py    # ELF parsing module (dependency)
├── README.md
```

---

## ⚙️ Requirements

- Python 3.8+
- Linux environment (recommended)
- Required module:
  - `ElfAnalyzer.py` (included or external dependency)

---

## 🛠️ Installation

```bash
git clone https://github.com/amrutamali6/ElfAnalyzer.git
cd ElfAnalyzer
```

(Optional) Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## ▶️ Usage

1. Update the ELF file path in the script:

```python
ELF_PATH = "/path/to/your/file.elf"
```

2. Run the analyzer:

```bash
python3 analyzer.py
```

---

## 📊 Example Output

### Hash Output

```
MD5       : <hash>
SHA1      : <hash>
SHA256    : <hash>
SHA512    : <hash>
```

### Suspicious Imports

```
total_hits: 23
categories_flagged: 6
```

### JSON Report

A file like:

```
sample_analysis.json
```

Generated with:

```json
{
  "file": "/path/to/file",
  "hashes": {
    "MD5": "...",
    "SHA1": "...",
    "SHA256": "...",
    "SHA512": "..."
  },
  "suspicious_imports": {
    "total_hits": 12,
    "categories_flagged": 4
  }
}
```

---

## 🧪 Use Cases

- Malware analysis
- Threat hunting
- Binary inspection
- Incident response
- Reverse engineering preparation

---

## 👤 Author

**Amruta Mali**
