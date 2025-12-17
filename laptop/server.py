# ----------------------------------------------------------
# server.py
# ----------------------------------------------------------
# Primary Author: Justin Morales (created the initial validator code and blockchain mechanisms)
# Secondary Author: Justin Turner (Miner and Dashboard integration + QA testing + editing)
# Acknowledgements: Chris Baden (Wrote an alternative, unused validator script)
#
# This code implements the validator node for the Cool-Coin DePIN network. 
# The validator manages and confirms transactions submitted by mining nodes. 
# Its main responsibilities are to verify, store, and process transactions. 
# 
# While this implementation runs as a single, centralized process, 
# it is designed as a conceptual model. In a full-scale system, multiple
# independent nodes would operate concurrently, each validating transactions.
# ----------------------------------------------------------

# -----Imports ----------------
import hashlib  # Provides SHA256 hashing to ensure integrity of data + transactions
import urllib.parse  # for decoding wallet addresss (URLs)
from fastapi import FastAPI, HTTPException  # FastAPI is used to create the HTTP server, HTTPException for errors
from pydantic import BaseModel  # Pydantic validates incoming request payloads against defined schemas
from datetime import datetime  # for transaction time stamps
import json, time, threading, base64
from cryptography.hazmat.primitives import serialization  # For loading public keys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # Ed25519 signing algorithm used
import os  # check file existence
from fastapi.middleware.cors import CORSMiddleware  # allow browser dashboards to fetch data on demand
from fastapi.responses import JSONResponse  # for returning latest_tx JSON nicely

# -----------------------------
# FastAPI Setup
# -----------------------------
app = FastAPI()  # create FastAPI application

# for the dashboard
app.add_middleware(
    CORSMiddleware,  # allow HTML dashboard to fetch data
    allow_origins=["*"],  # allow requests from any website, with no restrictions
    allow_credentials=True, # allow dashboard to include things like credentials or login info (unused)
    allow_methods=["*"], # allow all HTTP methods (GET, POST, PUT, DELETE). Crucial for dashboard operations
    allow_headers=["*"], # allows dashboard to send any header (unused)
)

# -----------------------------
# Global Data (whole sever can access)
# -----------------------------
blockchain = []  # list of all blocks we make
mempool = []  # transactions waiting to be put inside a block

latest_reading = None  # most recent sensor reading
latest_timestamp = None  # stores the timestamp of the latest transaction
BLOCK_TIME = 10  # every 10 seconds we make a block (how often coins get confirmed)


 
# -----------------------------
# Transaction Schema (What a valid transaction must look like)
# -----------------------------
class Transaction(BaseModel):
    type: str  # transaction type: "MINT" or "TRANSFER"
    from_addr: str  # PEM public key string (node ID)
    to_addr: str  # wallet recieving coins
    amount: float  # coins to transfer or mint
    reading: dict | None = None  # optional sensor reading (only used for MINT transactions)
    signature: str  # base64 Ed25519 signature created from sender's private key

# -----------------------------
# Server Utilities
# -----------------------------
CHAIN_FILE = "blockchain.json" 
MEMPOOL_FILE = "mempool.json"

# Save blockchain and mempool for persistent wallets 
def save_state():
    with open(CHAIN_FILE, "w") as f: # open file in write mode
        json.dump(blockchain, f, indent=2) #store blockchain state
    with open(MEMPOOL_FILE, "w") as f: # open file in write mode
        json.dump(mempool, f, indent=2) #store mempool state

# Load blockchain and mempool from local files
def load_state():
    global blockchain, mempool   # we want to update the global variables
    if os.path.exists(CHAIN_FILE): # if the file exists
        with open(CHAIN_FILE, "r") as f: # open it in read mode
            blockchain = json.load(f) # load
    if os.path.exists(MEMPOOL_FILE): # if the file exists
        with open(MEMPOOL_FILE, "r") as f:  # open it in read mode
            mempool = json.load(f) # load


# -----------------------------
# Blockchain Utilities
# -----------------------------
def hash_data(data): #Creates a SHA256 hash of the JSON-serialized block/transaction data.
    # The hash is used to verify integrity of blocks and transactions
    # if even a single bit changes, the hash changes completely.
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

# creates the first block so the chain has something to start with
def create_genesis():
    block = {
        "index": 0, #the first block always has index 0.
        "prev_hash": "0", # no previous block, so it’s set to
        "timestamp": str(datetime.utcnow()), # Records the current time (UTC) when the block is created
        "transactions": [], # No transactions in the first block. it’s empty.
        "block_hash": "" # Placeholder for the hash, it is calculated with the line below
    }
    
    # Computes a SHA256 hash of the block using the hash_data function from above
    # This hash uniquely identifies the block and ensures its integrity.
    block["block_hash"] = hash_data(block)  
    blockchain.append(block) # add the new genesis block to the the blockchain
    

# this runs forever and creates new blocks from mempool
def produce_blocks():
    while True: # produce blocks forever
        time.sleep(BLOCK_TIME) # pause for a fixed interval (BLOCK_TIME) controls how long a new block is produced
        if not mempool: # check if their are any transactions pending/waiting in the mempool
            continue # no transactions yet, skip the rest of the loop
        block = { 
            "index": len(blockchain), #current blockchain length
            "prev_hash": blockchain[-1]["block_hash"], #hash of the previous block
            "timestamp": str(datetime.utcnow()), # when the block is created.
            "transactions": mempool.copy() # all pending transactions copied from the mempool
        }
        # apply the transactions to balances

        mempool.clear() # clear mempool since they're now in a block
        block["block_hash"] = hash_data(block)  #Computes a hash for this new block to uniquely identify it
        blockchain.append(block) # block officially added
        save_state()


# -----------------------------
# Signature Verification
# -----------------------------
def verify_signature(tx):
    try:
        # load PEM public key from string
        pub_pem = tx["from_addr"].encode()
        vk = serialization.load_pem_public_key(pub_pem)   # verification key (Ed25519 public key) used to verify signature 
        msg_bytes = json.dumps(tx["reading"], sort_keys=True).encode() 
        vk.verify(base64.b64decode(tx["signature"]), msg_bytes)
        return True # if everything matches and there no errors -> signature is valid -> return true
    except Exception as e: # if anything goes wrong
        print("Signature verification failed:", e)
        return False





# -----------------------------
# Startup
# -----------------------------
# runs when we start the validator
@app.on_event("startup")
def start():
    # load_state() # load previous block chain states on startup (for persistent wallets) Experimental feature, turned off 
    if len(blockchain) == 0: #if the block chain hasn't been created yet
        create_genesis() # initate the chain with the genesis block
    threading.Thread(target=produce_blocks, daemon=True).start() # start a background thread that runs produce_blocks() infintely

# -----------------------------
# Endpoints
# -----------------------------
# sensors and wallets send transactions to the URL
@app.post("/submit_tx") #creates a POST endpoint at /submit_tx 
def submit_tx(tx: Transaction): 
    global latest_reading, latest_timestamp #allows the function to update global variables that track the latest reading and timestamp
    d = tx.dict() #using Pydantic to make data easier to handle
    # we check if the transaction is valid
    if d["type"] not in ("MINT", "TRANSFER"): #Only "MINT" or "TRANSFER" transactions are allowed
        raise HTTPException(400, "Unknown transaction type") #reject invalid types
    if not verify_signature(d):
        raise HTTPException(400, "Signature doesn't match") # reject invalid signatures


    # for TRANSFER transactions - check sender balance
    if d["type"] == "TRANSFER":
        sender = d["from_addr"]
        amount = d["amount"]
        balance = 0
    # Calculate confirmed balance from blockchain
        for block in blockchain: # scan blockchain
            for btx in block["transactions"]:
                if btx["type"] == "MINT" and btx["to_addr"] == sender:
                    balance += btx["amount"]
                elif btx["type"] == "TRANSFER":
                    if btx["to_addr"] == sender:
                        balance += btx["amount"]
                    if btx["from_addr"] == sender:
                        balance -= btx["amount"]

        # Include pending transactions in mempool
        for ptx in mempool: #scan mempool
            if ptx["type"] == "TRANSFER":
                if ptx["to_addr"] == sender:
                    balance += ptx["amount"]
                if ptx["from_addr"] == sender:
                    balance -= ptx["amount"]

        # Reject if insufficient funds
        if balance < amount:
            raise HTTPException(400, "Insufficient funds")

   
   
   
    d["timestamp"] = datetime.utcnow().strftime("%m-%d-%Y %H:%M:%S UTC")


    mempool.append(d) #Adds the transaction to the mempool



    #Updates the global variables for quick and efficient dashboard retrieval
    latest_reading = d.get("reading")
    latest_timestamp = d["timestamp"] #every transaction carries its own time stamp

    save_state()
    
    # server response
    return {
        "status": "Valid", # Valid Reading?
        "coins_rewarded": d["amount"], # Reward
        "timestamp": latest_timestamp ,# Time of transaction
        "type": d["type"]                # Transaction type (MINT or TRANSFER)
    }

# lets anyone see the whole blockchain
@app.get("/chain")
def get_chain():
    return blockchain


@app.get("/mempool") #retrieve the pending transactions
def get_mempool():
    # Just return the current mempool, dashboard uses it to compute pending coins
    return mempool