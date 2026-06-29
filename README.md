# paranoid.py

`paranoid.py` protects against a common but catastrophic scenario: your files being modified without your knowledge.

This can happen by accident or due to malice or bit rot. How would you know? This tool tells you.

I once met a photographer who managed over 100,000 photos with a diligent backup strategy. What he did not know was that most of his files were corrupted. By the time he realized, it was too late. He had been backing up corrupt files for years.

`paranoid.py` gives you certainty by tracking and detecting file changes in a directory tree.

The first time it runs, it creates a `__paranoid__.json` dictionary file containing each file's name, size, deep hash, and modification time. The dictionary file includes an embedded hash to verify its own integrity.

On subsequent runs, `paranoid.py` shows which files changed:

| Label | Meaning |
|---|---|
| ✨ `NEW` | file added |
| 🗑️ `DELETED` | file removed |
| ✏️ `UPDATED` | file contents changed |
| 🪱 `SUSPECT` | file contents changed but modification time did not — possible bit rot |
| 👯 `DUPES` | duplicate file found (verbose mode only) |

Changes can then be reviewed and saved to the dictionary file.

Quick mode (`--quick`) uses metadata fingerprints (size + modification time) for a faster but less thorough check.

