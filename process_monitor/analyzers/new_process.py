from datetime import datetime
from process_monitor.alert import ProcessAlert

# Helper/child processes that trusted, already-installed applications spawn
# constantly during normal use (browser tabs, GPU/render helpers, security
# suite background workers, console hosts). These generate a lot of
# NEW_PROCESS noise with essentially zero detection value. We match on the
# install path, not just the name, so a same-named file dropped somewhere
# else still gets flagged normally.
TRUSTED_NOISE_PATH_FRAGMENTS = [
    "\\microsoft\\edge\\", "\\google\\chrome\\", "\\mozilla firefox\\",
    "\\mcafee\\", "\\windows defender\\", "\\windows\\system32\\conhost.exe",
]

class NewProcessWatcher:
    def __init__(self):
        self._known_pids: set[int] = set()
        self._initialized = False

    def initialize(self, processes: list[dict]):
        """
        Call this once at startup with the initial list of processes.
        Everything in this list is considered 'normal' and will NOT be alerted.
        """
        self._known_pids = {p["pid"] for p in processes}
        self._initialized = True
        print(f"  [NewProcessWatcher] Learned {len(self._known_pids)} existing processes as baseline.")

    def analyze(self, process: dict) -> ProcessAlert | None:
        if not self._initialized:
            return None

        pid = process["pid"]

        # If we have never seen this PID before — it is a NEW process
        if pid not in self._known_pids:
            self._known_pids.add(pid)  # add it so we don't alert again
            name = process["name"]
            exe_path = (process.get("exe") or "").lower()

            # Skip routine helper processes from trusted, already-installed
            # vendors — they add noise without adding detection value.
            if any(frag in exe_path for frag in TRUSTED_NOISE_PATH_FRAGMENTS):
                return None

            return ProcessAlert(
                alert_type="NEW_PROCESS",
                severity="LOW",
                pid=pid,
                process_name=name,
                description=f"New process started: '{name}' (PID {pid}) — appeared after monitor started",
                extra={
                    "exe": process["exe"],
                    "username": process["username"],
                    "cmdline": process["cmdline"]
                }
            )

        return None