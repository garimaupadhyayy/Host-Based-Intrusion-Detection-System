import time
import os

LOG_FILE = "C:/Windows/Temp/test_hids.log"

print("This script will write test lines to your log file.")
print("Make sure run_log_monitor.py is running in another terminal first!")
print()

input("Press ENTER when your log monitor is running...")

# Test 1 - keyword detection
print("\nTest 1: Writing dangerous keyword line...")
with open(LOG_FILE, "a") as f:
    f.write("2026-05-11 12:01:00 ERROR rootkit detected on system drive\n")
print("Done! Watch your monitor terminal for a CRITICAL alert.")

time.sleep(4)   # wait 4 seconds so monitor picks it up

# Test 2 - brute force (write 6 failed logins)
print("\nTest 2: Simulating brute force attack (6 failed logins)...")
with open(LOG_FILE, "a") as f:
    for i in range(1, 7):
        f.write(f"2026-05-11 12:02:0{i} WARNING failed login attempt for user admin\n")
        print(f"  Wrote failed login #{i}")
        time.sleep(0.5)   # half second gap between each

print("\nDone! Watch your monitor terminal for a BRUTE_FORCE alert.")

time.sleep(4)

# Test 3 - error spike (write 12 errors fast)
print("\nTest 3: Simulating error spike (12 errors)...")
with open(LOG_FILE, "a") as f:
    for i in range(12):
        f.write(f"2026-05-11 12:03:{i:02d} ERROR Something went wrong in module {i}\n")
print("Done! Watch your monitor for an ERROR_SPIKE alert.")

print("\nAll tests complete!")