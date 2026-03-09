#!/bin/bash

VENV_PY="/home/anubhab/Downloads/OSfingerprinting/venv/bin/python3"

if [ "$1" = "-arp" ]; then
    echo "Running arpspoof..."
    sudo $VENV_PY arpSpoof.py "$2" &
    echo "Running fingerprint tool..."
    sudo $VENV_PY toolt.py "$2"

elif [ "$1" = "-tcp" ]; then
    if [ -z "$2" ]; then
        echo "Error: Please provide an IP address after -tcp."
        exit 1
    fi
    ip_address="$2"
    echo "Running tcp connector..."
    sudo $VENV_PY tcp_connector.py "$ip_address" &
    echo "Running fingerprint tool..."
    sudo $VENV_PY toolt.py "$ip_address"

else
    echo "Invalid choice. Use -arp or -tcp."
    exit 1
fi
