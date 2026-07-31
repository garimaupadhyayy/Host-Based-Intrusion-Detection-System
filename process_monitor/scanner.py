import psutil
from datetime import datetime

def get_all_processes():
    """
    Returns a list of all running processes with their details.
    Each process is a dictionary with name, PID, CPU usage, memory etc.
    """
    processes = []

    for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent',
                                      'memory_percent', 'exe', 'username',
                                      'create_time', 'cmdline']):
        try:
            info = proc.info

            # cpu_percent needs two calls to be accurate — first call returns 0.0
            # so we store it and the next scan will have real values
            processes.append({
                "pid": info['pid'],
                "name": info['name'] or "unknown",
                "status": info['status'],
                "cpu_percent": info['cpu_percent'] or 0.0,
                "memory_percent": round(info['memory_percent'] or 0.0, 2),
                "exe": info['exe'] or "",           # full path to the program file
                "username": info['username'] or "",
                "create_time": info['create_time'], # when process started (Unix timestamp)
                "cmdline": info['cmdline'] or [],   # command line used to start it
                "timestamp": datetime.now()
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Some system processes we can't read — skip them silently
            pass

    return processes