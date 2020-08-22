#!/usr/bin/env python3
import subprocess
import time

try:
    import scapy
except ModuleNotFoundError:
    print("Installing missing dependencies...")
    time.sleep(3)
    subprocess.call("apt-get update", shell=True)
    subprocess.call("apt-get install python3-pip -y", shell=True)
    subprocess.call("pip3 install scapy --quiet", shell=True)
finally:
    subprocess.call("clear", shell=True)
