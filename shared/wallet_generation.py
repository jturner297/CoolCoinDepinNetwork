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


# Only create wallet if it doesn't already exist
if os.path.exists("new_wallet.pem") or os.path.exists("new_wallet.pub"):
    print("Wallet already exists!") #inform user
else: #no pre-existing wallet, create new one
  
    # Generate a new Ed25519 private key
    private_key = Ed25519PrivateKey.generate() # This key will allow signing transactions


    # Save private key
    with open("new_wallet.pem", "wb") as f: # open file in write mode to store private key
        f.write(private_key.private_bytes( #convert key to PEM and write into file
            encoding=serialization.Encoding.PEM,  #use PEM text encoding
            format=serialization.PrivateFormat.PKCS8, # Standard private key format
            encryption_algorithm=serialization.NoEncryption() #no password protection 
        ))

 
    # Save public key

    # Extract matching public key from the private key
    # This key can be shared to receive coins
    public_key = private_key.public_key() 

    with open("new_wallet.pub", "wb") as f: # open file in write mode to store public key
        f.write(public_key.public_bytes(#convert key to PEM and write into file
         encoding=serialization.Encoding.PEM, #use PEM text encoding
         format=serialization.PublicFormat.SubjectPublicKeyInfo  # Standard public key format
        ))
    
    #confirmation message
    print("new_wallet created successfully!") #inform user
