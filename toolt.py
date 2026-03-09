import sys
import pandas as pd
from scapy.all import *
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import json
import warnings
import numpy as np
import random
import time

INTERFACE = "wlo1"
TIMEOUT = 20
PROBE_PORTS = [80, 443, 22, 445, 3389]
MAX_PACKETS = 8


# =========================
# MODEL TRAINING
# =========================
def train_model():
    print("[+] Loading dataset...")
    df = pd.read_excel("tcp_ip.xlsx")
    df.dropna(inplace=True)

    # Combine OS name and version for target
    df['os_full'] = df['os_name'] + " " + df['os_version'].astype(str)

    feature_indices = [11, 5, 2, 12, 26, 15, 21, 19]  # keep your current features
    target = 'os_full'

    X = df.iloc[:, feature_indices]
    y = df[target]

    encoder = LabelEncoder()
    y = encoder.fit_transform(y)

    X_train, _, y_train, _ = train_test_split(
        X, y, test_size=0.2, random_state=48
    )

    model = RandomForestClassifier(n_estimators=80, random_state=42)
    model.fit(X_train, y_train)

    print("[+] Model trained")
    return model, encoder


# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(pkt):
    if IP not in pkt:
        return None

    ip = pkt[IP]

    if TCP in pkt:
        tcp = pkt[TCP]
        return {
            "ip_len": ip.len,
            "tcp_window": tcp.window,
            "ip_id": ip.id,
            "tcp_offset": tcp.dataofs * 4,
            "ip_checksum": ip.chksum,
            "tcp_checksum": tcp.chksum,
            "tcp_seq": tcp.seq,
            "ttl": ip.ttl
        }

    if ICMP in pkt:
        return {
            "ip_len": ip.len,
            "tcp_window": 0,
            "ip_id": ip.id,
            "tcp_offset": 0,
            "ip_checksum": ip.chksum,
            "tcp_checksum": 0,
            "tcp_seq": 0,
            "ttl": ip.ttl
        }

    return None


# =========================
# PROBES
# =========================
def send_probes(target_ip):
    print("[+] Sending TCP probes...")
    for port in PROBE_PORTS:
        sport = random.randint(1024, 65535)
        send(IP(dst=target_ip) / TCP(sport=sport, dport=port, flags="S"), verbose=0)

    print("[+] Sending ICMP probe...")
    send(IP(dst=target_ip) / ICMP(), verbose=0)


# =========================
# ML ANALYSIS ONLY
# =========================
def analyze_packets(collected, model, encoder):
    print("[+] Analyzing collected packets...")

    ttl_avg = int(np.mean([p["ttl"] for p in collected]))
    tcp_window = next((p["tcp_window"] for p in collected if p["tcp_window"] != 0), 0)
    sample = collected[0]

    feature_vector = [[
        sample["ip_len"],
        tcp_window,
        sample["ip_id"],
        sample["tcp_offset"],
        sample["ip_checksum"],
        sample["tcp_checksum"],
        sample["tcp_seq"],
        ttl_avg
    ]]

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        probs = model.predict_proba(feature_vector)[0]
        pred_index = np.argmax(probs)
        confidence = float(probs[pred_index])
        label = encoder.inverse_transform([pred_index])[0]

    result = {
        "title": label,
        "confidence": round(confidence * 100, 2),
        "method": "ml",
        "avg_ttl": ttl_avg,
        "packets_used": len(collected)
    }

    print(json.dumps(result, indent=2))


# =========================
# MAIN ACTIVE FINGERPRINT
# =========================
def run_active_fingerprint(target_ip):
    conf.use_pcap = True

    print("[+] Active fingerprinting started")
    print(f"[+] Interface: {INTERFACE}")
    print(f"[+] Target   : {target_ip}")

    model, encoder = train_model()
    collected = []

    def process_packet(pkt):
        if IP not in pkt:
            return

        if pkt[IP].src != target_ip:
            return

        features = extract_features(pkt)
        if not features:
            return

        collected.append(features)
        print(f"[+] Packet {len(collected)}/{MAX_PACKETS} captured")

    print("[+] Starting sniffer...")

    sniffer = AsyncSniffer(
        iface=INTERFACE,
        filter=f"src host {target_ip}",
        prn=process_packet,
        store=0
    )

    sniffer.start()
    time.sleep(1)

    send_probes(target_ip)

    start = time.time()
    while time.time() - start < TIMEOUT:
        if len(collected) >= MAX_PACKETS:
            break
        time.sleep(0.5)

    sniffer.stop()

    if collected:
        analyze_packets(collected, model, encoder)
    else:
        print("[!] Timeout — no responses received")
        sys.exit(1)


# =========================
# ENTRY
# =========================
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 toolt.py <TARGET_IP>")
        sys.exit(1)

    run_active_fingerprint(sys.argv[1])
