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
import os
import pickle

MODEL_FILE = "rf_model.pkl"         # NEW
ENCODER_FILE = "label_encoder.pkl"  # NEW

INTERFACE = "wlo1"
TIMEOUT = 20
PROBE_PORTS = [2221, 22, 80, 443, 445, 3389]
MAX_PACKETS = 12

# =========================
# FEATURE DEFINITIONS
# =========================
# We exclude long-flow and reverse features since active probing 
# captures isolated response packets, not full bidirectional flows.
USED_FEATURES = [
    'TTL', 
    'TCP_WIN', 
    'TCP_MSS', 
    'TCP_SYN_SIZE'
]
# =========================
# MODEL TRAINING
# =========================
def train_model():
    
    if os.path.exists(MODEL_FILE) and os.path.exists(ENCODER_FILE):
        print(f"[+] Loading existing model from {MODEL_FILE}...")
        with open(MODEL_FILE, 'rb') as mf, open(ENCODER_FILE, 'rb') as ef:
            model = pickle.load(mf)
            encoder = pickle.load(ef)
    else:
        print("[+] Loading dataset...")
        file_numbers = range(2, 3) 
        files = [f'subnet{i}.csv' for i in file_numbers]

        # Read and combine
        df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
        
        # Drop rows missing essential features or the target label
        df.dropna(subset=USED_FEATURES + ['OS_LABEL'], inplace=True)
        
        X = df[USED_FEATURES]
        y = df['OS_LABEL']

        encoder = LabelEncoder()
        y = encoder.fit_transform(y)

        # stratify=y ensures minority operating systems are represented in both splits
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=48, stratify=y
        )

        model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=6, class_weight='balanced')
        model.fit(X_train, y_train)

        print(f"[+] Model trained on {len(X_train)} samples with active features.")

        print("[+] Saving model and encoder to disk for future runs...")
        with open(MODEL_FILE, 'wb') as mf, open(ENCODER_FILE, 'wb') as ef:
            pickle.dump(model, mf)
            pickle.dump(encoder, ef)

    return model, encoder


# =========================
# FEATURE EXTRACTION
# =========================
def round_ttl(ttl):
    """Rounds TTL to the nearest higher power of two (e.g., 64, 128, 256)"""
    if ttl <= 0: 
        return 0
    return 2 ** (ttl - 1).bit_length()

def extract_features(pkt):
    if IP not in pkt:
        return None

    ip = pkt[IP]
    
    # Base extracted features
    features = {
        "TTL": round_ttl(ip.ttl),
        "TCP_WIN": 0,
        "TCP_MSS": 0,
        "TCP_SYN_SIZE": ip.len, 
        "TCP_OPTIONS": 0,
        "TCP_FLAGS": 0,
        "PROTOCOL": ip.proto
    }

    if TCP in pkt:
        tcp = pkt[TCP]
        features["TCP_WIN"] = tcp.window
        features["TCP_FLAGS"] = int(tcp.flags)
        
        mss = 0
        opt_bitfield = 0
        
        # Convert TCP Options into a basic bitfield 
        # (MSS=1, WScale=2, SAckOK=4, Timestamp=8, NOP=16)
        for opt in tcp.options:
            if opt[0] == 'MSS':
                mss = opt[1]
                opt_bitfield |= 1
            elif opt[0] == 'WScale':
                opt_bitfield |= 2
            elif opt[0] == 'SAckOK':
                opt_bitfield |= 4
            elif opt[0] == 'Timestamp':
                opt_bitfield |= 8
            elif opt[0] == 'NOP':
                opt_bitfield |= 16
        
        features["TCP_MSS"] = mss
        features["TCP_OPTIONS"] = opt_bitfield
    print(f"[DEBUG] Extracted features: {features}")
    return features


# =========================
# PROBES
# =========================
def send_probes(target_ip):
    print("[+] Sending TCP probes with rich options...")
    
    # We include standard options to negotiate full TCP features
    # This forces the target OS to reply with its unique combination of supported options
    rich_options = [
        ('MSS', 1460), 
        ('SAckOK', ''), 
        ('Timestamp', (int(time.time() % 10000), 0)), 
        ('NOP', None), 
        ('WScale', 7)
    ]
    
    for port in PROBE_PORTS:
        sport = random.randint(1024, 65535)
        # Add the options array to our outgoing SYN
        probe = IP(dst=target_ip) / TCP(sport=sport, dport=port, flags="S", options=rich_options)
        send(probe, verbose=0)

    print("[+] Sending ICMP probe...")
    send(IP(dst=target_ip) / ICMP(), verbose=0)

# =========================
# ML ANALYSIS ONLY
# =========================
def analyze_packets(collected, model, encoder):
    print("[+] Analyzing collected packets...")

    # We want to feed the AI the most informative packet. 
    # A reply to our SYN with a SYN-ACK (flags=18) contains the richest TCP data.
    best_pkt = None
    for p in collected:
        if p["PROTOCOL"] == 6 and p["TCP_FLAGS"] == 18:
            best_pkt = p
            break
    
    # Fallback to the first collected packet if no SYN-ACK was captured
    if not best_pkt:
        best_pkt = collected[0]

    feature_vector = [[
        best_pkt["TTL"],
        best_pkt["TCP_WIN"],
        best_pkt["TCP_MSS"],
        best_pkt["TCP_SYN_SIZE"],
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
        "ttl_used": best_pkt["TTL"],
        "packets_captured": len(collected)
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
        if len(collected) >= MAX_PACKETS:
            return
        if IP not in pkt:
            return

        # Ensure we only process returning traffic from the target
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
        print("Usage: python3 newtool.py <TARGET_IP>")
        sys.exit(1)

    run_active_fingerprint(sys.argv[1])