#!/usr/bin/env python3
"""
Windows Binary Hardening Checker
Author: MichalRybecky (https://github.com/MichalRybecky)
"""

import argparse
import os
import pefile
import csv
from tabulate import tabulate
from colorama import Fore, Style, init as colorama_init

colorama_init()  # Enable color output on Windows

# -------------------------------------------
# Utility Functions for Binary Checks
# -------------------------------------------

def check_aslr(pe):
    """Check for ASLR: DYNAMIC_BASE flag in DllCharacteristics"""
    try:
        return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)
    except Exception:
        return False

def check_dep(pe):
    """Check for DEP: NX_COMPAT flag in DllCharacteristics"""
    try:
        return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x100)
    except Exception:
        return False

def check_cfg(pe):
    """Check for CFG: GUARD_CF flag in DllCharacteristics"""
    try:
        return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000)
    except Exception:
        return False

def check_safeseh(pe):
    """Check for SafeSEH: only applicable to 32-bit binaries"""
    try:
        if pe.FILE_HEADER.Machine != 0x14c:  # IMAGE_FILE_MACHINE_I386
            return "N/A"
        return pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']].VirtualAddress != 0 and \
               hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') and \
               hasattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct, 'SafeSEH') and \
               pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SafeSEH != 0
    except Exception:
        return False

def check_signature(pe, filepath):
    """Check for Authenticode signature (very basic check)"""
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        return sec_dir.Size > 0
    except Exception:
        return False

def check_pe(filepath):
    """Return dictionary of check results for given file"""
    try:
        pe = pefile.PE(filepath, fast_load=True)
    except Exception:
        return None  # Not a PE file

    return {
        'aslr': check_aslr(pe),
        'dep': check_dep(pe),
        'cfg': check_cfg(pe),
        'safeseh': check_safeseh(pe),
        'signed': check_signature(pe, filepath),
        'arch': 'x86' if pe.FILE_HEADER.Machine == 0x14c else 'x64',
    }

def is_pe_file(filepath):
    """Rudimentary check for PE file"""
    try:
        with open(filepath, 'rb') as f:
            mz = f.read(2)
            return mz == b'MZ'
    except Exception:
        return False

# -------------------------------------------
# Directory Traversal & Scanning
# -------------------------------------------

def scan_directory(directory, recursive=True, verbose=False):
    """Yield file paths of .exe/.dll files in directory (and subdirectories if recursive)"""
    for root, _, files in os.walk(directory):
        for name in files:
            if name.lower().endswith(('.exe', '.dll')):
                full_path = os.path.join(root, name)
                if verbose:
                    print(f"{Fore.CYAN}Scanning:{Style.RESET_ALL} {full_path}")
                yield full_path
        if not recursive:
            break

# -------------------------------------------
# Output Formatting
# -------------------------------------------

def result_to_row(filepath, result):
    """Format result for table/CSV/Markdown with Yes/No/N/A"""
    if result is None:
        return [filepath, "N/A", "N/A", "N/A", "N/A", "N/A"]
    return [
        filepath,
        "Yes" if result['aslr'] else "No",
        "Yes" if result['dep'] else "No",
        "Yes" if result['cfg'] else "No",
        result['safeseh'] if result['safeseh'] == "N/A" else ("Yes" if result['safeseh'] else "No"),
        "Yes" if result['signed'] else "No"
    ]

def write_csv(rows, output_file):
    with open(output_file, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["File", "ASLR", "DEP", "CFG", "SafeSEH", "Signed"])
        writer.writerows(rows)

def write_md(rows, output_file):
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("| File | ASLR | DEP | CFG | SafeSEH | Signed |\n")
        f.write("|------|------|-----|-----|---------|--------|\n")
        for row in rows:
            f.write("| " + " | ".join(str(col) for col in row) + " |\n")

def print_table(rows):
    print(tabulate(rows, headers=["File", "ASLR", "DEP", "CFG", "SafeSEH", "Signed"], tablefmt="github"))

# -------------------------------------------
# Main CLI
# -------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scan Windows binaries for ASLR, DEP, CFG, SafeSEH, and Signature."
    )
    parser.add_argument("-d", "--directory", required=True, help="Directory to scan")
    parser.add_argument("--csv", help="Output CSV file")
    parser.add_argument("--md", help="Output Markdown file")
    parser.add_argument("-r", "--recursive", action="store_true", default=True, help="Recursively scan subfolders (default: True)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"{Fore.RED}[!] Directory does not exist:{Style.RESET_ALL} {args.directory}")
        exit(1)

    results = []
    file_count = 0
    checked = 0

    print(f"{Fore.GREEN}Scanning directory:{Style.RESET_ALL} {args.directory}\n")

    for filepath in scan_directory(args.directory, recursive=args.recursive, verbose=args.verbose):
        file_count += 1
        result = None
        if is_pe_file(filepath):
            result = check_pe(filepath)
            checked += 1
        row = result_to_row(filepath, result)
        results.append(row)

    print_table(results)
    print(f"\n{Fore.YELLOW}Total files scanned: {file_count}, PE files checked: {checked}{Style.RESET_ALL}\n")

    if args.csv:
        write_csv(results, args.csv)
        print(f"{Fore.GREEN}[+] CSV report written to:{Style.RESET_ALL} {args.csv}")
    if args.md:
        write_md(results, args.md)
        print(f"{Fore.GREEN}[+] Markdown report written to:{Style.RESET_ALL} {args.md}")

if __name__ == "__main__":
    main()

