import os
import time

class LogFileWatcher:
    """
    Watches a single log file and yields only NEW lines as they appear.
    Think of it like 'tail -f' in Linux — it follows the file from the end.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._position = 0   # remember where we left off in the file

    def get_new_lines(self) -> list[str]:
        """
        Returns any new lines added to the file since last check.
        Returns empty list if nothing new.
        """
        new_lines = []

        if not os.path.exists(self.filepath):
            return new_lines  # file doesn't exist yet — that's okay

        try:
            with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
                # Jump to where we last stopped reading
                f.seek(self._position)

                for line in f:
                    stripped = line.strip()
                    if stripped:   # ignore blank lines
                        new_lines.append(stripped)

                # Remember our new position in the file
                self._position = f.tell()

        except (PermissionError, OSError):
            # Can't read this file right now — skip silently
            pass

        return new_lines

    def reset(self):
        """Go back to the beginning of the file."""
        self._position = 0