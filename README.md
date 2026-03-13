<div align="center">
OS Fingerprinting using Machine Learning

An active, machine-learning-powered network reconnaissance tool that predicts the Operating System of a target device by analyzing its TCP/IP stack behavior.

</div>
Table of Contents

    Overview

    Features

    Dataset Schema

    Prerequisites

    Usage

    Troubleshooting

Overview

Unlike traditional passive fingerprinting tools (like p0f) that rely on static, hardcoded signature databases, this tool takes an active approach. It sends specialized "rich" TCP SYN probes to force the target OS to reveal its advanced stack limits, and then uses a trained Random Forest Classifier to predict the Operating System based on the nuanced differences in network stack implementations.
Features

    Active Probing: Uses scapy to send specialized SYN packets loaded with TCP options (MSS, Window Scaling, Timestamps, SACK).

    Machine Learning Analysis: Uses scikit-learn to classify the OS based on the network response.

    Bias-Resistant Training: Explicitly limits decision tree depth and restricts features to strict OS limits (TTL, Window Size, MSS, SYN Size) to avoid "client vs. server" prediction biases.

    Model Caching: Automatically saves the trained model (rf_model.pkl) to disk for lightning-fast execution on subsequent runs.

Dataset Schema

The model is trained on network flow data from the subnet1, subnet2, subnet3, and subnet4 datasets.

    Note on Feature Selection: While the datasets contain full bidirectional flow metrics, this active fingerprinting tool intentionally restricts its training and inference to a strict subset (TTL, TCP_WIN, TCP_MSS, and TCP_SYN_SIZE). This prevents the AI from falsely correlating flow sizes (Bytes/Packets) or ephemeral ports with a specific OS.

Included Features:
Feature	Description
OS_LABEL	OS annotation label (Target Variable)
DST_PORT	Transport layer destination port
SRC_PORT	Transport layer source port
TCP_SYN_SIZE	TCP SYN packet size
TCP_WIN	TCP window size
TCP_WIN_REV	TCP window size (reverse)
TCP_MSS	TCP maximum segment size
PACKETS	Number of packets in data flow (src to dst)
PACKETS_REV	Number of packets in data flow (dst to src)
BYTES	Number of bytes in data flow (src to dst)
BYTES_REV	Number of bytes in data flow (dst to src)
TCP_OPTIONS	TCP options bitfield
TCP_OPTIONS_REV	TCP options bitfield (reverse)
DIR_BIT_FIELD	Bit field for determining outgoing/incoming traffic
FLOW_END_REASON	FlowEndReason [RFC5102]
L3_FLAGS	L3 FLAGS
L3_FLAGS_REV	L3 FLAGS (reverse)
PROTOCOL	Transport protocol
TCP_FLAGS	TCP protocol flags (src to dst)
TTL	IP TTL field (rounded to nearest higher power of two)
TTL_REV	IP TTL field (reverse)
Prerequisites

You need Python 3 installed along with the following libraries. Install them via pip:
Bash

pip install pandas scikit-learn scapy numpy

Usage

Because the tool crafts raw network packets and actively sniffs the interface for replies, it must be run with root/administrator privileges.
Command Syntax
Bash

sudo python3 newtool.py <TARGET_IP>

Arguments
Argument	Description	Example
<TARGET_IP>	(Required) The IP address of the device to fingerprint.	10.0.0.45
Example Run
Bash

sudo python3 newtool.py 10.0.0.45 -i wlo1

Expected Output
JSON

[+] Active fingerprinting started
[+] Interface: wlo1
[+] Target   : 10.0.0.45
[+] Loading existing model from rf_model.pkl...
[+] Starting sniffer on wlo1...
[+] Sending 'Rich' TCP probes...
[+] Sending ICMP probe...
[+] Analyzing collected packets...
{
  "title": "linux",
  "confidence": 88.5,
  "method": "ml",
  "ttl_used": 64,
  "packets_used": 3
}

Troubleshooting

    Model predicts incorrectly or outputs "Timeout"

        Cause: The target device likely has all probed ports closed, or is behind a strict firewall/AP Isolation. It is replying with RST packets (which strip TCP options) or dropping packets entirely.

        Fix: Ensure the target device has at least one open port, and verify that your machine can reach it (e.g., test with ping or nmap).

    Want to retrain the model? * Cause: You updated the datasets or tweaked the hyperparameters, but the script is still using the old cached model.

        Fix: Delete the cached .pkl files by running rm rf_model.pkl label_encoder.pkl. The script will automatically parse your datasets and train a fresh model on its next run.