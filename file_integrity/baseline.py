import json
import os
from datetime import datetime

DEFAULT_BASELINE_FILE = "hids_baseline.json"

class BaselineDB:
    """
    Stores and retrieves file hashes in a JSON file.
    Think of it as a safe record of what every watched file looked like
    when it was known to be clean.
    """

    def __init__(self, db_path: str = DEFAULT_BASELINE_FILE):
        self.db_path = db_path
        self._data: dict = {}   # {filepath: {"hash": ..., "saved_at": ...}}
        self._load()

    def _load(self):
        """Load existing baseline from disk if it exists."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    self._data = json.load(f)
                print(f"  [Baseline] Loaded {len(self._data)} file records from {self.db_path}")
            except (json.JSONDecodeError, OSError):
                self._data = {}
                print(f"  [Baseline] Could not load {self.db_path} — starting fresh.")
        else:
            print(f"  [Baseline] No existing baseline found. Will create one.")

    def save(self):
        """Write current baseline to disk."""
        try:
            with open(self.db_path, "w") as f:
                json.dump(self._data, f, indent=2)
        except OSError as e:
            print(f"  [Baseline] Could not save: {e}")

    def set(self, filepath: str, file_hash: str):
        """Store a file's hash in the baseline."""
        self._data[filepath] = {
            "hash": file_hash,
            "saved_at": datetime.now().isoformat()
        }

    def get(self, filepath: str) -> str | None:
        """Get a file's stored hash. Returns None if not in baseline."""
        entry = self._data.get(filepath)
        return entry["hash"] if entry else None

    def remove(self, filepath: str):
        """Remove a file from the baseline (e.g. if it was legitimately deleted)."""
        self._data.pop(filepath, None)

    def all_tracked_files(self) -> list[str]:
        """Returns list of all files currently in the baseline."""
        return list(self._data.keys())

    def is_empty(self) -> bool:
        return len(self._data) == 0