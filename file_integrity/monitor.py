import os
import time
import threading
import logging
from collections import deque
from typing import Callable

from file_integrity.hasher import compute_hash, get_file_metadata
from file_integrity.baseline import BaselineDB
from file_integrity.alert import FileAlert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s"
)
logger = logging.getLogger(__name__)

SCAN_INTERVAL_SECONDS = 10   # check files every 10 seconds

# How severe should each type of change be?
# You can change these — critical system files should be CRITICAL
SEVERITY_MAP = {
    "FILE_MODIFIED": "HIGH",
    "FILE_DELETED":  "CRITICAL",
    "FILE_CREATED":  "MEDIUM",
}

class FileIntegrityMonitor:
    def __init__(
        self,
        watch_paths: list[str],           # files OR folders to watch
        baseline_file: str = "hids_baseline.json",
        on_alert: Callable[[FileAlert], None] = None
    ):
        """
        watch_paths: list of files or folders to monitor.
                     If a folder is given, all files inside are watched.
        baseline_file: where to save the hash database
        on_alert: function to call when something changes
        """
        self._watch_paths = watch_paths
        self._on_alert = on_alert
        self._alert_log = deque(maxlen=500)
        self._running = False
        self._baseline = BaselineDB(baseline_file)

    def _collect_all_files(self) -> list[str]:
        """
        Expands folders into individual file paths.
        Returns a flat list of every file to watch.
        """
        all_files = []
        for path in self._watch_paths:
            if os.path.isfile(path):
                all_files.append(path)
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    # Skip hidden folders like .git
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    for fname in files:
                        all_files.append(os.path.join(root, fname))
        return all_files

    def build_baseline(self):
        """
        First-time setup: scan all files and save their hashes.
        Call this once when you know the system is clean.
        """
        logger.info("Building baseline — scanning all watched files...")
        files = self._collect_all_files()
        count = 0
        for filepath in files:
            h = compute_hash(filepath)
            if h:
                self._baseline.set(filepath, h)
                count += 1
        self._baseline.save()
        logger.info(f"Baseline built! {count} files fingerprinted and saved.")

    def start(self):
        self._running = True

        # If no baseline exists yet, build it now
        if self._baseline.is_empty():
            logger.info("No baseline found — building one now...")
            self.build_baseline()
            logger.info("Baseline ready. Now watching for changes...\n")
        else:
            logger.info("Baseline loaded. Watching for changes...\n")

        logger.info(f"Scanning every {SCAN_INTERVAL_SECONDS} seconds.\n")

        thread = threading.Thread(target=self._scan_loop, daemon=True)
        thread.start()
        thread.join()

    def stop(self):
        self._running = False
        logger.info("File integrity monitor stopped.")

    def get_alerts(self) -> list[FileAlert]:
        return list(self._alert_log)

    def _fire_alert(self, alert: FileAlert):
        self._alert_log.append(alert)
        logger.warning(f"ALERT >> {alert.alert_type} | {alert.description}")
        if self._on_alert:
            self._on_alert(alert)

    def _scan_loop(self):
        while self._running:
            current_files = set(self._collect_all_files())
            tracked_files = set(self._baseline.all_tracked_files())

            # ── Check existing files for modifications ──────────────────
            for filepath in current_files:
                current_hash = compute_hash(filepath)
                if not current_hash:
                    continue

                saved_hash = self._baseline.get(filepath)

                if saved_hash is None:
                    # File exists on disk but NOT in baseline = new file created
                    self._baseline.set(filepath, current_hash)
                    self._baseline.save()
                    meta = get_file_metadata(filepath)
                    self._fire_alert(FileAlert(
                        alert_type="FILE_CREATED",
                        severity=SEVERITY_MAP["FILE_CREATED"],
                        filepath=filepath,
                        description=f"New file appeared: '{os.path.basename(filepath)}'",
                        extra={"size_bytes": meta.get("size_bytes", 0)}
                    ))

                elif current_hash != saved_hash:
                    # File is in baseline BUT hash changed = file was modified
                    self._baseline.set(filepath, current_hash)
                    self._baseline.save()
                    meta = get_file_metadata(filepath)
                    self._fire_alert(FileAlert(
                        alert_type="FILE_MODIFIED",
                        severity=SEVERITY_MAP["FILE_MODIFIED"],
                        filepath=filepath,
                        description=f"File was modified: '{os.path.basename(filepath)}'",
                        extra={
                            "old_hash": saved_hash[:16] + "...",
                            "new_hash": current_hash[:16] + "...",
                            "size_bytes": meta.get("size_bytes", 0)
                        }
                    ))

            # ── Check for deleted files ─────────────────────────────────
            for filepath in tracked_files:
                if not os.path.exists(filepath):
                    self._baseline.remove(filepath)
                    self._baseline.save()
                    self._fire_alert(FileAlert(
                        alert_type="FILE_DELETED",
                        severity=SEVERITY_MAP["FILE_DELETED"],
                        filepath=filepath,
                        description=f"File was DELETED: '{os.path.basename(filepath)}'",
                        extra={"full_path": filepath}
                    ))

            time.sleep(SCAN_INTERVAL_SECONDS)