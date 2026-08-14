"""
veilscan/__main__.py
====================
Enables running VeilScan as a module:

    python -m veilscan scanme.nmap.org --profile quick --agree

Also serves as the pip entry point after installation:

    veilscan scanme.nmap.org --profile quick --agree

Why this file is needed
-----------------------
When installed via pip, Python looks for the entry point defined in
pyproject.toml:

    [project.scripts]
    veilscan = "veilscan.__main__:main"

This means Python will call main() from veilscan/__main__.py.
Previously this file imported from root-level main.py which is NOT
installed by pip — causing ModuleNotFoundError after pip install.

Now cli.py (veilscan/cli.py) contains all the CLI logic. This file
simply imports from it so both 'python -m veilscan' and the installed
'veilscan' command work correctly.
"""

from veilscan.cli import main

if __name__ == "__main__":
    import sys
    sys.exit(main())
