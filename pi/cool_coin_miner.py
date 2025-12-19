# ----------------------------------------------------------
# cool_coin_miner.py
# ----------------------------------------------------------
# Author - Justin Turner
#
# This code turns the Raspberry Pi into a mining node  
# for the Cool-Coin DePIN network.  
#
# It's job is to continuously collect real-world environmental
# data (temperature, pressure, humidity) using a BME280 sensor.
#
# Each data reading is digitally signed using the Pi’s
# private key to prove authenticity.
#
# The signed reading is then sent to a validator node.
# The validator verifies the signature, checks data freshness,
# and issues Cool-Coin rewards for valid submissions.
# ----------------------------------------------------------


# -----Imports -------------------------------------------

import time            # used for sleeping/pausing between sensor readings
import csv             # used to write sensor readings to local CSV file 
from datetime import datetime  # Allows us to get the current date and time. Used for timestamps in the CSV file

import requests          # for HTTP POST
import json            # used to build the JSON message payload
import base64          # used to base64-encode the signature bytes

# Hardware-related Imports
import board           # gives access to Pi pins
import busio           # handles I2C communication
from adafruit_bme280 import basic as adafruit_bme280  # sensor driver (handles low level communication so that I dont have to write directly to the sensor)

# cryptography imports for loading and using Ed25519 keys (Ed25519 = algorithm for public-key cryptography)
from cryptography.hazmat.primitives import serialization  # lets us load/store keys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey # uses Ed25519's signing ability, allowing us to sign json payload with private key

import os # for clearing the terminal


# -----Initializations -------------------------------------------

# Initialize the BME280 sensor over I2C
i2c = busio.I2C(board.SCL, board.SDA)          # create an I2C connection on SCL/SDA pins
bme280 = adafruit_bme280.Adafruit_BME280_I2C(i2c)  # initialize the sensor with that I2C bus
WALLET_DIR = os.path.join("..", "shared", "wallets")  # path that points to ../shared/wallets               # all wallets stored here
CONFIG_FILE = "miner_config.json"


# Miner/Node identity (NOT a wallet)
NODE_ID_DIR = os.path.join("..", "pi", "ID") # Build the path to the directory that stores this node's identity keys
NODE_PRIV_KEY_PATH = os.path.join(NODE_ID_DIR, "node_ed25519.pem") # Full path to the node's private key file
NODE_PUB_KEY_PATH  = os.path.join(NODE_ID_DIR, "node_ed25519.pub") # Full path to the node's public key file



# -----Function definitions -------------------------------------------
def load_or_init_node_ID():
    """
    Load or initialize the node's identity.

    - This identity uniquely represents the physical device (Pi).
    - It is generated once on first run and reused forever.
    - It is NOT a wallet and never receives funds directly.
    
    """

    # Make sure the identity directory exists 
    os.makedirs(NODE_ID_DIR, exist_ok=True)

    # --------------------
    # First-run check
    # --------------------

    # If the private key does not exist - this is the first time this node is running
    if not os.path.exists(NODE_PRIV_KEY_PATH):

        # Inform the user that a new node identity is being created
        print("\nGenerating node ID...")

        # Generate a brand-new Ed25519 private key for this node
        node_private_key = Ed25519PrivateKey.generate()

        # Derive the corresponding public key from the private key
        node_public_key = node_private_key.public_key()

        # --------------------
        # Save private key
        # --------------------

        # Open the private key file in binary write mode
        with open(NODE_PRIV_KEY_PATH, "wb") as f:

            # Serialize and write the private key in PEM format
            f.write(
                node_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,            # PEM text encoding
                    format=serialization.PrivateFormat.PKCS8,        # Standard private key format
                    encryption_algorithm=serialization.NoEncryption() # No password (device-bound key)
                )
            )

        # --------------------
        # Save public key
        # --------------------

        # Open the public key file in binary write mode
        with open(NODE_PUB_KEY_PATH, "wb") as f:

            # Serialize and write the public key in PEM format
            f.write(
                node_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,             # PEM text encoding
                    format=serialization.PublicFormat.SubjectPublicKeyInfo  # Standard public key format
                )
            )

        # Confirm successful creation
        print("Node ID established.\n")
        

    # --------------------
    # Load existing identity
    # --------------------

    # Open the node's private key file in binary read mode
    with open(NODE_PRIV_KEY_PATH, "rb") as f:

        # Deserialize the private key from PEM format
        node_private_key = serialization.load_pem_private_key(
            f.read(),        # Read the entire file
            password=None    # No password was used when saving
        )

    # Open the node's public key file in binary read mode
    with open(NODE_PUB_KEY_PATH, "rb") as f:

        # Read, decode, and strip the public key so it can be sent in JSON
        node_public_key_pem = f.read().decode().strip()



    # Return both keys for use by the miner
    return node_private_key, node_public_key_pem

def load_config(config_file=CONFIG_FILE):
    """
    Read config from disk.
    """
    
    # Check whether this is the first time the program is running
    first_run = not os.path.exists(config_file)

    # If this is NOT the first run
    if not first_run:
        with open(config_file, "r") as f: # open the existing config up
            config = json.load(f) #load JSON data from file
            
    else: # first run, create empty config
        config = {}
        
    # Current values
    return first_run, config

def load_wallet(wallet_name):
    """
    Load the public key for a given wallet name.
    Exits the program if the key does not exist or the name is empty.
    Returns: public_key_pem (address to send reward to)
    """

    # Make sure the wallet name is not empty
    if not wallet_name:
        print("Wallet name cannot be empty.") 
        return None 

    # construct full paths to public key
    public_key_path  = os.path.join(WALLET_DIR, f"{wallet_name}.pub")

    # Wallet Existence Check 
    if not os.path.exists(public_key_path): # public key is not present
        print(f"ERROR: '{wallet_name}' wallet public key can't be load: does not exist in directory!\n")
        return None # back out and return nothing

    try: #try to load wallet address
         # load public key
        with open(public_key_path, "rb") as f:         # open the public key file
            public_key_pem = f.read().decode().strip() # store the text version for JSON output (turn into normat text bytes)
   
    except Exception as e: # failed to load wallet
        print("Failed to load wallet public key:", e) #inform user
        return None  # back out and return nothing
    
    return public_key_pem # return the wallet address data


def init_config(node_public_key_pem, config_file=CONFIG_FILE):
    
    print("\n--- Initial Node Setup ---") #banner

    # prompt user
    server_ip = input("\nEnter validator server IP (e.g., 192.168.1.1): ").strip() 
    server_port = input("Enter validator server port (e.g., 8000): ").strip()
    
    wallet_name = input("Enter the wallet name to recieve rewards: ").strip()
    public_key_pem = load_wallet(wallet_name)

    node_nickname = input("Enter a nickname for this node: ").strip()
       
       
    # build config with user input
    config = {
        "server_ip": server_ip,
        "server_port": server_port,
        "wallet_name": wallet_name,
        "node_nickname": node_nickname,
    }

    # Save new config
    with open(config_file, "w") as f:
        json.dump(config, f, indent=4)
    
    register_node_nickname(server_ip, server_port, node_public_key_pem, node_nickname) # try to register nickname with server
    
    server_url = f"http://{server_ip}:{server_port}/submit_tx" #build full validator url

    return server_ip, server_port, server_url, wallet_name, node_nickname, public_key_pem
# --------------------
# Menus
# --------------------
def sub_menu():
    """
    Display a menu for the user before mining starts.
    Options:
        1. Update Config
        2. View Config
        3. Return Main Menu
    """
    global server_ip, server_port, server_url
    global wallet_name, node_nickname
    
    while True:
        print("\n-------Node Config-------")
        print("1. Reset Config")
        print("2. View Config")
        print("3. Back")
        print() #skip line
        choice = input("Select an option: ").strip()

        if choice == "1":
            # Update server IP/port using the config
            (
            server_ip,
            server_port,
            server_url,
            wallet_name,
            node_nickname,
            new_public_key_pem
            ) = update_config(CONFIG_FILE)

            if new_public_key_pem is not None:
                public_key_pem = new_public_key_pem
  

        elif choice == "2":
            
            # Display wallet info   
            print() #skip line
            print("-"*60)
            print(f"Using validator server at: {server_url}")
            print(f"Node name: {node_nickname}")
            print(f"Wallet name: {wallet_name}")
            print("-"*60)
            
            print() #skip line

        elif choice == "3":
            # Return to main menu
            return
        else:
            # Invalid choice handler
            print("\nInvalid option, please try again.")

def main_menu():
    """
    Display a menu for the user before mining starts.
    Options:
        1. Start Mining
        2. Reset/View Config
        3. Exit
    """
    global server_ip, server_port, server_url
    global wallet_name
    
    while True:
        print("\n-------Main Menu-------")
        print("1. Start Mining")
        print("2. Reset/View Config")
        print("3. Exit program")
        print() #skip line
        choice = input("Select an option: ").strip()

        if choice == "1":
            # Start mining (exit menu)
            if public_key_pem  is None:           
                    print("\nCannot start mining: wallet public key not loaded. Please update your wallet in the config menu first.\n")
                    continue  # force them to stay in main menu
            
            print("\nStarting mining...")
            break

        elif choice == "2":
            # Optional Config Menu
            sub_menu() 

        elif choice == "3":
            # Exit program gracefully
            print("\nExiting program")
            exit(0)

        else:
            # Invalid choice handler
            print("Invalid option, please try again.")

# ---------------------------------------------------
#  Send nickname to validator (optional, for dashboard)
# ---------------------------------------------------
def register_node_nickname(server_ip, server_port, node_pubkey_pem, node_nickname):
    """
    Send this node's nickname to the validator for dashboard resolution.
    
    - node_pub_key_pem: Node's Ed25519 public key (unique identifier)
    - node_nickname: The nickname string
    - server_ip: Validator IP
    - server_port: Validator port
    
    This does NOT sign the nickname. The validator only stores it
    and resolves duplicates.
    """
    
    # Build URL for nickname endpoint
    url = f"http://{server_ip}:{server_port}/submit_nickname"
    
    # Build the JSON payload
    payload = {
        "pubkey": node_pubkey_pem, # node ID (pi public key)
        "nickname": node_nickname  # human-readable nickname
    }
    
    try:
         # Make a POST request to the validator
        r = requests.post(url, json=payload, timeout=2)
        resp = r.json()
        if resp.get("status") == "success":
            print(f"Nickname '{node_nickname}' registered with validator successfully.\n")
        else:
            print(f"Validator rejected nickname '{node_nickname}': {resp.get('reason', 'Unknown')}\n")
    except Exception as e:
        print(f"Failed to register nickname with validator: {e}\n")
        

def update_config(config_file=CONFIG_FILE):
    """
    Interactively update config fields one-by-one.
    Only modifies fields the user explicitly chooses.
    """
    first_run, config = load_config(config_file)
    
    server_ip, server_port, server_url, wallet_name, node_nickname = get_config_values(config)
    
    nickname_changed = False
    wallet_changed   = False
    
    print("\n--- Update Node Configuration ---\n")
    
    print(f"Validator IP: {server_ip}")
    if input("Update validator IP? (y/N): ").strip().lower() == "y":
        server_ip = input("Enter new validator IP: ").strip()
        config["server_ip"] = server_ip

    print(f"\nValidator Port: {server_port}")
    if input("Update validator port? (y/N): ").strip().lower() == "y":
        server_port = input("Enter new validator port: ").strip()
        config["server_port"] = server_port

    print(f"\nWallet name: {wallet_name}")
    if input("Update wallet? (y/N): ").strip().lower() == "y":
        wallet_name = input("Enter new wallet name: ").strip()
        config["wallet_name"] = wallet_name
        wallet_changed = True

    print(f"\nNode nickname: {node_nickname}")
    if input("Update node nickname? (y/N): ").strip().lower() == "y":
        new_nickname = input("Enter new node nickname: ").strip()
        if new_nickname != node_nickname:
            node_nickname = new_nickname
            config["node_nickname"] = node_nickname
            nickname_changed = True
    
    # Save config
    with open(config_file, "w") as f:
        json.dump(config, f, indent=4)

    # Side effects
    public_key_pem = None

    if wallet_changed:
        public_key_pem = load_wallet(wallet_name)

    if nickname_changed:
        node_pubkey_flat = node_public_key_pem.replace("\n", "")
        register_node_nickname(server_ip, server_port, node_pubkey_flat, node_nickname)

    server_url = f"http://{server_ip}:{server_port}/submit_tx"

    return server_ip, server_port, server_url, wallet_name, node_nickname, public_key_pem
    
def get_config_values(config):
    server_ip     = config.get("server_ip")
    server_port   = config.get("server_port")
    wallet_name   = config.get("wallet_name")
    node_nickname = config.get("node_nickname")

    server_url = None
    if server_ip and server_port:
        server_url = f"http://{server_ip}:{server_port}/submit_tx"

    return server_ip, server_port, server_url, wallet_name, node_nickname     
# 1. Load or intitiaizle node ID (Critical Step)
node_private_key, node_public_key_pem = load_or_init_node_ID()

# 2. Load config metadata
first_run, config = load_config()

# if config does not exist yet

if first_run:  # Run first-time initialization
    (
        server_ip,
        server_port,
        server_url,
        wallet_name,
        node_nickname,
        public_key_pem
    ) = init_config(node_public_key_pem)
else:
    server_ip, server_port, server_url, wallet_name, node_nickname = get_config_values(config)
    server_url    = f"http://{server_ip}:{server_port}/submit_tx"

    public_key_pem = load_wallet(wallet_name)

# 4. Open main menu
main_menu()


# Open the CSV file to log readings locally (not used in crypto project - just cool to look at)
with open("bme280_log.csv", "a", newline="") as csvfile:  # appemd to the CSV file
    writer = csv.writer(csvfile)                          # CSV writer object
   
    #CSV formatting (again, not used in crypto project)
    start = datetime.now().strftime("%m-%d-%Y | %H:%M:%S")
    writer.writerow([f"----------------------{start}----------------------"])
    writer.writerow(["     Timestamp","  Temperature (C)", "  Pressure (hPa)", "  Humidity (%)"])  # header row in CSV file
    writer.writerow([f"-----------------------------------------------------------------"])


    # ------------------------------------------------------
    # Main Infinite Loop
    # ------------------------------------------------------
    while True:
        try:
            # Read sensor values
            temp = bme280.temperature       # temperature in Celsius
            pres = bme280.pressure          # air pressure in hPa 
            hum = bme280.humidity           # humidity in % 

          
            # Write readings to CSV file (not used in crypto project)
            timestamp = datetime.now().strftime("%m-%d %H:%M:%S")   # Get current date & time
            writer.writerow([timestamp, f"{temp:.2f}", f"{pres:.2f}", f"{hum:.2f}"]) #write line to CSV
            csvfile.flush()                 # make sure the file writes immediately

            # --------------------------------------------------
            # Preparing the payload
            # --------------------------------------------------
           
           
            # Sign the reading
            sensor_readings={ # packs up the individual readings into a package for the payload
                "temperature": round(temp, 2),
                "pressure": round(pres, 2),
                "humidity": round(hum, 2)
            }           

            # prepare signature for payload
            
            #convert readings into JSON string and turns it into bytes.
            message = json.dumps(sensor_readings, sort_keys=True).encode()
            
             # sign bytes from above using node's private key
             # resulting in a long sequence of pytes that proves the message came from this device (Pi)
            signature_bytes = node_private_key.sign(message)
           
           # convert bytes into base64 so they can be placed in the JSON payload safely
           # This is not encryption, it is just making it so that it can be printable in the end
            signature_b64 = base64.b64encode(signature_bytes).decode()  

            # -----------------------------------------------------------------
            # Build the JSON message payload to send to the server (validator)
            # -----------------------------------------------------------------
            tx_payload = {
                "type": "MINT", #transaction type is always MINT (creating coins)
                "from_addr": node_public_key_pem,  # node ID
                "to_addr": public_key_pem, # wallet receiving coins
                "amount": 1, # coins to reward
                "reading": sensor_readings, # sensor data
                "signature": signature_b64 # Ed25519 signature of the reading
            }
        


            # --------------------------------------------------
            # Try to receive a reply 
            # --------------------------------------------------
            try:
                # Send the transaction to the validator
                r = requests.post(server_url, json=tx_payload, timeout=1) # send tx
                resp = r.json()  # Convert the JSON response from the validator to a Python dictionary

            except Exception as e:    
                # Use a fallback response so the rest of the code doesn't crash
                resp = {
                'status': 'Server Down',
                'coins_rewarded': 0,
                 'timestamp': 'MM-DD-YYYY --:--:-- UTC',
                 'type': 'MINT'
                }

             
            # Terminal Dashboard Formatting 
            os.system('cls' if os.name == 'nt' else 'clear')  # clear the Pi terminal (gives it a clean look)
            
            #print the dashboard
            print("="*50)
            print(" " * 16 + "Cool-Coin Miner")
            print("="*50)
            
            timestamp = resp.get('timestamp', 'Unknown') #valid transaction return timestamp, invalid return unknown
            print(timestamp.center(50))  


            # Sensor readings
            
            
            print(f"\nSensing Node: {node_nickname }")
            print(f"Payout Wallet: {wallet_name}" , "\n")
            print("Readings:")
            print(f"    {'Temperature':<12}: {temp:6.2f} °C")
            print(f"    {'Pressure':<12}:  {pres:6.2f} hPa")
            print(f"    {'Humidity':<12}: {hum:6.2f} %")

            # Server/Validator Reply
            print("\nServer:")
            if resp.get('status') is not None:
             print(f"    {'Status':<12}: {resp.get('status')}")
            else:
             print(f"    {'Status':<12}: Invalid")
        
            if resp.get('coins_rewarded') is not None:
             print(f"    {'Reward':<12}: {resp.get('coins_rewarded'):.2f} Cool-Coins")
            else:
             print(f"    {'Reward':<12}: 0")
            

            print("="*50 + "\n")
            
   
            

            # wait 1 second before next reading (mines every second)
            time.sleep(1)


        except KeyboardInterrupt:  # If the user presses Ctrl+C....
            # stop gracefully
            print("\nStopping sensor reading and HTTP sending...")
            break
