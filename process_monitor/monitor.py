import time
import threading
import logging
from collections import deque
from typing import Callable

from process_monitor.scanner import get_all_processes
from process_monitor.analyzers.resource_abuse import ResourceAbuseDetector
from process_monitor.analyzers.suspicious_process import SuspiciousProcessDetector
from process_monitor.analyzers.new_process import NewProcessWatcher
from process_monitor.alert import ProcessAlert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s"
)
logger = logging.getLogger(__name__)

SCAN_INTERVAL_SECONDS = 5   # how often to check (change to 3 for faster scans)

class ProcessMonitor:
    def __init__(self, on_alert: Callable[[ProcessAlert], None] = None):
        self._on_alert = on_alert
        self._alert_log = deque(maxlen=500)
        self._running = False

        # Create all analyzers
        self._resource_detector = ResourceAbuseDetector()
        self._suspicious_detector = SuspiciousProcessDetector()
        self._new_process_watcher = NewProcessWatcher()

        self._analyzers = [
            self._resource_detector,
            self._suspicious_detector,
            self._new_process_watcher,
        ]

    def start(self):
        self._running = True
        logger.info("Process monitor starting...")

        # First scan — build the baseline (what is 'normal')
        logger.info("Taking baseline snapshot of current processes...")
        initial_processes = get_all_processes()
        self._new_process_watcher.initialize(initial_processes)
        logger.info(f"Baseline done. Found {len(initial_processes)} running processes.")
        logger.info(f"Scanning every {SCAN_INTERVAL_SECONDS} seconds. Watching for threats...\n")

        # Start the monitoring loop in a background thread
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()
        thread.join()  # wait here until stopped

    def stop(self):
        self._running = False
        logger.info("Process monitor stopped.")

    def get_alerts(self) -> list[ProcessAlert]:
        """For dashboard — returns all alerts so far."""
        return list(self._alert_log)

    def _monitor_loop(self):
        while self._running:
            processes = get_all_processes()

            for process in processes:
                for analyzer in self._analyzers:
                    try:
                        alert = analyzer.analyze(process)
                        if alert:
                            self._alert_log.append(alert)
                            logger.warning(
                                f"ALERT >> {alert.alert_type} | {alert.description}"
                            )
                            if self._on_alert:
                                self._on_alert(alert)
                    except Exception as e:
                        logger.error(f"Analyzer error: {e}")

            time.sleep(SCAN_INTERVAL_SECONDS)