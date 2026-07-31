import time
import threading
import logging
from collections import deque
from typing import Callable

from log_monitor.watcher import LogFileWatcher
from log_monitor.parser import parse_line
from log_monitor.analyzers.brute_force import BruteForceDetector
from log_monitor.analyzers.error_spike import ErrorSpikeDetector
from log_monitor.analyzers.keyword_detector import KeywordDetector
from log_monitor.alert import LogAlert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s"
)
logger = logging.getLogger(__name__)

POLL_INTERVAL = 2   # check for new log lines every 2 seconds

class LogMonitor:
    def __init__(self, log_files: list[str], on_alert: Callable[[LogAlert], None] = None):
        """
        log_files: list of full paths to log files you want to watch
        on_alert:  function to call when an alert is raised
        """
        self._log_files = log_files
        self._on_alert = on_alert
        self._alert_log = deque(maxlen=500)
        self._running = False

        # Create one watcher per log file
        self._watchers = {
            path: LogFileWatcher(path) for path in log_files
        }

        # Create all analyzers (shared across all log files)
        self._analyzers = [
            BruteForceDetector(),
            ErrorSpikeDetector(),
            KeywordDetector(),
        ]

    def start(self):
        self._running = True
        logger.info(f"Log monitor started. Watching {len(self._log_files)} file(s):")
        for f in self._log_files:
            logger.info(f"   -> {f}")
        logger.info(f"Checking for new lines every {POLL_INTERVAL} seconds...\n")

        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()
        thread.join()

    def stop(self):
        self._running = False
        logger.info("Log monitor stopped.")

    def get_alerts(self) -> list[LogAlert]:
        return list(self._alert_log)

    def _monitor_loop(self):
        while self._running:
            for filepath, watcher in self._watchers.items():
                new_lines = watcher.get_new_lines()

                for raw_line in new_lines:
                    parsed = parse_line(raw_line, filepath)

                    for analyzer in self._analyzers:
                        try:
                            alert = analyzer.analyze(parsed)
                            if alert:
                                self._alert_log.append(alert)
                                logger.warning(
                                    f"ALERT >> {alert.alert_type} | {alert.description}"
                                )
                                if self._on_alert:
                                    self._on_alert(alert)
                        except Exception as e:
                            logger.error(f"Analyzer error on '{filepath}': {e}")

            time.sleep(POLL_INTERVAL)