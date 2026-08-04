# OpenReverse Python Automation Script
# Automatically scans imported DLLs and dumps suspicious section headers
import openreverse as rev

def scan_pe_sections():
    sections = rev.get_pe_sections()
    for s in sections:
        print(f'Section: {s.name} - VirtualSize: {hex(s.virtual_size)}')

if __name__ == '__main__':
    scan_pe_sections()
