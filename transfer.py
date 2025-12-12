
# ----------------------------------------------------------
# transfer.py
# ----------------------------------------------------------
# Author: Justin Turner
#
# This script sends a TRANSFER transaction from Wallet 1 to Wallet 2
# on the Cool-Coin network via the validator.
# ----------------------------------------------------------

import json
import requests
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datetime import datetime

# ----------------------------
# Load Wallets
# ----------------------------
def load_wallet(private_pem_file, public_pem_file):
    with open(private_pem_file, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(public_pem_file, "r") as f:
        pub_key_pem = f.read().strip()
    return priv_key, pub_key_pem

# ----------------------------
# Load Wallet 2's Public Key Only
# ----------------------------
def load_public_key(public_pem_file):
    with open(public_pem_file, "r") as f:
        return f.read().strip()

wallet1_priv, wallet1_pub = load_wallet("mywallet.pem", "mywallet.pub") #need wallet 1's pub and priv for signing
wallet2_pub = load_public_key("wallet2.pub")  # Only need Wallet 2's public key

# ----------------------------
# Transaction Parameters
# ----------------------------
server_url = "http://192.168.137.1:8000/submit_tx"  # Validator endpoint

#Transfer Amount
while True:
    try:
        amount_to_send = float(input("Enter amount of Cool-Coins to transfer: "))
        if amount_to_send <= 0:
            print("Amount must be greater than 0.")
            continue
        break
    except ValueError:
        print("Invalid number. Please enter a numeric amount.")


# ----------------------------
# Build & Sign Transaction Payload
# ----------------------------
tx_data = {
    "type": "TRANSFER",
    "from_addr": wallet1_pub,
    "to_addr": wallet2_pub,
    "amount": amount_to_send,
    "reading": None  # Not needed for transfer
}

# Sign transaction
message = json.dumps(None, sort_keys=True).encode()  # since reading=None
signature_bytes = wallet1_priv.sign(message)
tx_data["signature"] = base64.b64encode(signature_bytes).decode()

# ----------------------------
# Add Timestamp (optional, validator adds its own too)
# ----------------------------
tx_data["timestamp"] = datetime.utcnow().strftime("%m-%d-%Y %H:%M:%S UTC")

# ----------------------------
# Send Transaction to Validator
# ----------------------------
try:
    resp = requests.post(server_url, json=tx_data, timeout=2)
    resp_json = resp.json()
     # If server returns error inside HTTP 400/500, resp_json may have 'detail'
    if "detail" in resp_json:
        error_message = resp_json["detail"]
        # Turn it into dashboard-style info
        resp_json = {
            "status": f"Error: {error_message}",
            "coins_transferred": 0,
            "timestamp": tx_data["timestamp"],
            "type": tx_data["type"]
        }
except Exception as e:
   # Network or request error
    resp_json = {
        "status": f"Error sending transaction: {e}",
        "coins_transferred": 0,
        "timestamp": tx_data["timestamp"],
        "type": tx_data["type"]
    }

# ----------------------------
# Print Dashboard
# ----------------------------
print("="*50)
print(" " * 16 + "Cool-Coin Transfer")
print("="*50)

# Transaction Info
timestamp = resp_json.get('timestamp', 'Unknown') #valid transaction return timestamp, invalid return unknown
print(timestamp.center(50))  

print()
print(f"{'Status':<20}: {resp_json.get('status', 'Unknown')}")
print(f"{'Type':<20}: {resp_json.get('type', 'TRANSFER')}")
print(f"{'Amount':<20}: {amount_to_send:.2f} Cool-Coins")

print("="*50 + "\n")