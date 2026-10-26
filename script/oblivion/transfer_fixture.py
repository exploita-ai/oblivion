"""Public synthetic data for the isolated file-copy laboratory only."""
ID = "0123456789abcdef0123456789abcdef"
CANARY = b"OBLIVION_COPY_VM_CANARY_318a"
FILES = {
    "documents/città.txt": CANARY + b"\n",
    "documents/large.bin": bytes(range(251)) * 1300,
    "documents/empty": b"",
    "documents/archive.zip": b"PK\x03\x04" + CANARY,
}

if __name__ == "__main__":
    import sys
    from pathlib import Path
    root = Path(sys.argv[1])
    for name, data in FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (root / "documents/empty-directory").mkdir()
    (root / "unselected.txt").write_bytes(b"not selected")
