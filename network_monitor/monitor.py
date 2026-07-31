import queue
import threading
import logging
from collections import deque
from scapy.all import sniff
from network_monitor.parser import parse_packet
from network_monitor.analyzers.port_scan import PortScanDetector
from network_monitor.analyzers.dns import DNSAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s"
)
logger = logging.getLogger(__name__)

class NetworkMonitor:
    def __init__(self, iface=None, on_alert=None):
        self._pkt_queue = queue.Queue(maxsize=5000)
        self._alert_log = deque(maxlen=500)
        self._on_alert = on_alert
        self._iface = iface
        self._running = False

        self._analyzers = [
            PortScanDetector(),
            DNSAnalyzer(),
        ]

    def start(self):
        self._running = True
        logger.info("Network monitor started. Watching traffic...")

        worker = threading.Thread(target=self._process_loop, daemon=True)
        worker.start()

        sniff(
            iface=self._iface,
            filter="ip",
            prn=self._on_packet,
            store=False,
            stop_filter=lambda _: not self._running
        )

    def stop(self):
        self._running = False
        logger.info("Network monitor stopped.")

    def get_alerts(self):
        return list(self._alert_log)

    def _on_packet(self, pkt):
        parsed = parse_packet(pkt)
        if parsed:
            try:
                self._pkt_queue.put_nowait(parsed)
            except queue.Full:
                pass

    def _process_loop(self):
        while self._running:
            try:
                parsed = self._pkt_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            for analyzer in self._analyzers:
                try:
                    alert = analyzer.analyze(parsed)
                    if alert:
                        self._alert_log.append(alert)
                        logger.warning(f"ALERT >> {alert.alert_type} | {alert.description}")
                        if self._on_alert:
                            self._on_alert(alert)
                except Exception as e:
                    logger.error(f"Analyzer error: {e}")