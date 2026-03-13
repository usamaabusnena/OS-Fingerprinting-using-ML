OS Fingerprinting using Machine Learning

This project uses an active machine-learning approach to fingerprint the Operating System (OS) of a target device over a network.

Unlike traditional passive fingerprinting tools that rely on hardcoded signature databases (like p0f), this tool actively sends "rich" TCP SYN probes to elicit a response and uses a trained Random Forest Classifier to predict the target OS based on its network stack behavior.
Features

    Active Probing: Uses scapy to send specialized SYN packets loaded with TCP options (MSS, Window Scaling, Timestamps, SACK) to force the target OS to reveal its advanced stack limits.

    Machine Learning Analysis: Uses Scikit-Learn to classify the OS based on the response.

    Bias-Resistant Training: The model explicitly limits its decision tree depth and restricts features to strict OS limits (TTL, Window Size, MSS, SYN Size) to avoid overfitting and "client vs. server" prediction biases.

    Model Caching: Automatically saves the trained model (rf_model.pkl) to disk to ensure lightning-fast subsequent runs.

Dataset Schema

The model is trained on network flow data. Below is the schema for the features included in datasets subnet1, subnet2, subnet3, and subnet4:
Feature	Description
OS_LABEL	OS annotation label
DST_PORT	transport layer destination port
SRC_PORT	transport layer source port
TCP_SYN_SIZE	TCP SYN packet size
TCP_WIN	TCP window size
TCP_WIN_REV	TCP window size
TCP_MSS	TCP maximum segment size
PACKETS	number of packets in data flow (src to dst)
PACKETS_REV	number of packets in data flow (dst to src)
BYTES	number of bytes in data flow (src to dst)
BYTES_REV	number of bytes in data flow (dst to src)
TCP_OPTIONS	TCP options bitfield
TCP_OPTIONS_REV	TCP options bitfield
DIR_BIT_FIELD	bit field for determining outgoing/incoming traffic
FLOW_END_REASON	FlowEndReason [RFC5102]
L3_FLAGS	L3 FLAGS
L3_FLAGS_REV	L3 FLAGS
PROTOCOL	transport protocol
TCP_FLAGS	TCP protocol flags (src to dst)
TTL	IP TTL field (rounded to nearest higher power of two)
TTL_REV	IP TTL field

    Note on Feature Selection: While the datasets contain full bidirectional flow metrics, the active fingerprinting tool intentionally restricts its training and inference to a subset of these features (specifically TTL, TCP_WIN, TCP_MSS, and TCP_SYN_SIZE). This prevents the AI from falsely correlating network sizes (like Bytes or Packets) or ephemeral ports with a specific Operating System.

Prerequisites

You need Python 3 installed along with the following libraries:
Bash

pip install pandas scikit-learn scapy numpy

Usage

Because the tool crafts raw network packets and actively sniffs the interface for replies, it must be run with root/administrator privileges.
Bash

sudo python3 newtool.py <TARGET_IP> -i <INTERFACE>

Arguments:

    <TARGET_IP>: The IP address of the device you want to fingerprint (e.g., 192.168.1.5).

    -i / --interface: The network interface to sniff on (e.g., eth0, wlan0, wlo1, en0).

Example:
Bash

sudo python3 newtool.py 10.0.0.45 -i wlo1

Output Example:
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

    Model predicts incorrectly or outputs "Timeout": Ensure the target device has at least one open port. If all ports are closed or the device is behind a strict firewall/AP Isolation, it will reply with RST packets (stripping its TCP options) or drop the packets entirely, significantly reducing the model's accuracy.

    Want to retrain the model? If you update the datasets, simply delete the .pkl files in the directory. The script will automatically train a fresh model on its next run.
