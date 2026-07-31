import hashlib
import os

def compute_hash(filepath: str) -> str | None:
    """
    Computes a SHA-256 hash (fingerprint) of a file.
    Returns None if the file cannot be read.

    SHA-256 means: even changing one letter in a 1GB file
    gives a completely different hash. Perfect for detecting tampering.
    """
    sha256 = hashlib.sha256()

    try:
        with open(filepath, "rb") as f:   # "rb" = read as raw bytes
            # Read in chunks so large files don't crash the program
            while chunk := f.read(65536):  # 64 KB at a time
                sha256.update(chunk)
        return sha256.hexdigest()          # returns a 64-character string

    except (PermissionError, FileNotFoundError, OSError):
        return None


def get_file_metadata(filepath: str) -> dict:
    """
    Gets basic file info — size and last modified time.
    Useful to include in alerts.
    """
    try:
        stat = os.stat(filepath)
        return {
            "size_bytes": stat.st_size,
            "last_modified": stat.st_mtime,
        }
    except OSError:
        return {}