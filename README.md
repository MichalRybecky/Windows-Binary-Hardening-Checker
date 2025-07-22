# Windows Binary Hardening Checker

A Python CLI tool to scan Windows executables (`.exe`, `.dll`) for common binary hardening/security features.

Useful for blue teams, penetration testers, and system administrators to ensure binaries are compiled with recommended mitigations.

---

## Features

- Recursively scans folders for Windows PE binaries (`.exe`, `.dll`)
- Checks for:
  - **ASLR** (Address Space Layout Randomization)
  - **DEP** (Data Execution Prevention)
  - **CFG** (Control Flow Guard)
  - **SafeSEH**
  - **Authenticode signature** (signed/unsigned)
- Output as:
  - Pretty table (console)
  - CSV file (`--csv`)
  - Markdown table (`--md`)
- Minimal dependencies

---

## Quick Start

1. **Clone the repo:**
    ```sh
    git clone https://github.com/MichalRybecky/windows-binary-hardening-checker.git
    cd windows-binary-hardening-checker
    ```

2. **Install requirements:**
    ```sh
    pip install -r requirements.txt
    ```

3. **Run the tool:**
    ```sh
    python main.py -d "C:\Path\To\Folder"
    ```

4. **Options:**
    ```sh
    python main.py -h
    ```
    ```
    usage: main.py [-h] -d DIRECTORY [--csv CSV_OUTPUT] [--md MD_OUTPUT] [-r] [-v]

    options:
      -h, --help            show this help message and exit
      -d DIRECTORY, --directory DIRECTORY
                            Directory to scan
      --csv CSV_OUTPUT      Output results as CSV to this file
      --md MD_OUTPUT        Output results as Markdown to this file
      -r, --recursive       Recursively scan subfolders (default: True)
      -v, --verbose         Verbose output
    ```

---

## Example Output

**Console Table:**

| File                            | ASLR | DEP | CFG | SafeSEH | Signed |
| ------------------------------- | ---- | --- | --- | ------- | ------ |
| C:\Windows\System32\notepad.exe | Yes  | Yes | No  | N/A     | Yes    |
| C:\Windows\System32\bad.exe     | No   | No  | No  | No      | No     |


**CSV/Markdown:**
- See `/examples/sample_output.csv`
- See `/examples/sample_output.md`

---

## Limitations

- Only works on Windows
- Checks only PE (Portable Executable) files
- SafeSEH is relevant only for 32-bit (x86) binaries
- Some fields may display "N/A" where not applicable

---

## License

MIT License

---

_Author: [Michal Rybecky](https://github.com/MichalRybecky)_

