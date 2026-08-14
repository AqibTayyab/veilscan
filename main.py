"""
main.py — VeilScan v2.0 root entry point.

This file exists so users can run VeilScan directly from the
project folder without pip installing:

    python main.py scanme.nmap.org --profile quick --agree

All CLI logic lives in veilscan/cli.py so it works after pip install.
This file simply delegates to it.

Usage modes
-----------
  Direct:      python main.py <target> [options]
  Module:      python -m veilscan <target> [options]
  Installed:   veilscan <target> [options]
  Wizard:      python main.py   (no args — interactive menu)
"""

import sys
import os

# Allow running from project root without pip install
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from veilscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
