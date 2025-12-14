# ----------------------------------------------------------
# wallet_generation.py
# ----------------------------------------------------------
# Author: Justin Turner 
# 
# Generates a new wallet (public/private key pair) 
# for signing and receiving transactions
# 
# This code was made for testing transfers from Pi's wallet 
# to Laptop. It is meant to be ran on laptop.
# ----------------------------------------------------------

# Imports
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey # lets us generate Ed25519 private keys
from cryptography.hazmat.primitives import serialization # lets us save keys in PEM format
import os


# Wallet Directoty
WALLET_DIR = "wallets"                     # folder where all wallets will be stored
os.makedirs(WALLET_DIR, exist_ok=True)     # create wallet folder if it doesn't already exist

# Ask for wallet name
wallet_name = input(
    "Enter wallet name (e.g. miner, laptop, test1, Justin): "
).strip()                                  # remove any accidental spaces

# Ensure wallet name is not empty
if not wallet_name:
    print("Wallet name cannot be empty.")  # inform user of invalid input
    exit(1)         

#Build File Paths

private_key_path = os.path.join(
    WALLET_DIR, f"{wallet_name}.pem"
)                                          # full path to private key file

public_key_path = os.path.join(
    WALLET_DIR, f"{wallet_name}.pub"
)                                          # full path to public key file

# Safety Check - Prevent accidental overwriting of an existing wallet
if os.path.exists(private_key_path) or os.path.exists(public_key_path):
    print(f"Wallet '{wallet_name}' already exists!")   # inform user
    print("Aborting wallet generation.")               # explain reason
    exit(1)                                            # exit safely



# Generate a new Ed25519 private key
private_key = Ed25519PrivateKey.generate() # This key will allow signing transactions

# Save private key
with open(private_key_path, "wb") as f: # open file in write mode to store private key
    f.write(private_key.private_bytes( #convert key to PEM and write into file
            encoding=serialization.Encoding.PEM,  #use PEM text encoding
            format=serialization.PrivateFormat.PKCS8, # Standard private key format
            encryption_algorithm=serialization.NoEncryption() #no password protection 
    ))

# Save public key

# Extract matching public key from the private key
# This key can be shared to receive coins
public_key = private_key.public_key() 

with open(public_key_path, "wb") as f:   # open file in write mode to store public key
        f.write(public_key.public_bytes(#convert key to PEM and write into file
         encoding=serialization.Encoding.PEM, #use PEM text encoding
         format=serialization.PublicFormat.SubjectPublicKeyInfo  # Standard public key format
    ))
    
#confirmation message
print("\nWallet created successfully!")     # success message
print(f"Wallet name : {wallet_name}")       # show wallet identifier
print(f"Private key : {private_key_path}")  # show private key path
print(f"Public key  : {public_key_path}")   # show public key path
