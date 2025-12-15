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

# Initialize the BME280 sensor over I2C
i2c = busio.I2C(board.SCL, board.SDA)          # create an I2C connection on SCL/SDA pins
bme280 = adafruit_bme280.Adafruit_BME280_I2C(i2c)  # initialize the sensor with that I2C bus

bme280.sea_level_pressure = 1013.25            # optional calibration for altitude calculations (unused)


WALLET_DIR = os.path.join("..", "shared", "wallets")  # points to ../shared/wallets               # all wallets stored here
CONFIG_FILE = "miner_config.json"
# --------------------
# Function definitions
# --------------------

def load_wallet(wallet_name):
    """
    Load the private and public keys for a given wallet name.
    Exits the program if the wallet does not exist or the name is empty.
    Returns: private_key, public_key_pem, private_key_path, public_key_path
    """

    # Make sure the wallet name is not empty
    if not wallet_name:
        print("Wallet name cannot be empty.") 
        return None, None, None, None

    # construct full paths to private/public keys
    private_key_path = os.path.join(WALLET_DIR, f"{wallet_name}.pem")
    public_key_path  = os.path.join(WALLET_DIR, f"{wallet_name}.pub")

    # Wallet Existence Check 
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        print(f"Wallet '{wallet_name}' does not exist!")
        print(f"Make sure {private_key_path} and {public_key_path} exist.\n")
        return None, None, None, None

    try: 
        # load private key
        with open(private_key_path, "rb") as f:              # open the private key file
         private_key = serialization.load_pem_private_key(
               f.read(),                               # read the file contents
               password=None                           # no password on the key
          )
         # load public key
        with open(public_key_path, "rb") as f:         # open the public key file
            public_key_pem = f.read().decode().strip() # store the text version for JSON output (turn into normat text bytes)
    except Exception as e:
        print("Failed to load wallet:", e)
        return None, None, None, None
    
    print(f"Loaded wallet '{wallet_name}' successfully!\n")
    return private_key, public_key_pem, private_key_path, public_key_path

def load_or_init_config(config_file=CONFIG_FILE, force_edit=False):
    """
    Load server config and wallet name from JSON.
    If first run → mandatory setup.
    If force_edit=True → re-prompt user and overwrite values.
    Returns: server_ip, server_port, server_url, wallet_name
    """
    first_run = not os.path.exists(config_file)

    if not first_run:
        with open(config_file, "r") as f:
            config = json.load(f)
    else:
        config = {}

    server_ip = config.get("server_ip")
    server_port = config.get("server_port")
    wallet_name = config.get("wallet_name")

    # First run banner
    if first_run:
        print("=" * 50)
        print(" " * 16 + "Miner Setup")
        print("=" * 50)

    # ---------- PROMPT LOGIC ----------
    # Prompt if missing OR if user explicitly wants to edit
    if first_run or force_edit or not server_ip:
        server_ip = input("\nEnter validator server IP (e.g., 192.168.1.1): ").strip()
        config["server_ip"] = server_ip

    if first_run or force_edit or not server_port:
        server_port = input("Enter validator server port (e.g., 8000): ").strip()
        config["server_port"] = server_port

    if first_run or force_edit or not wallet_name:
        wallet_name = input("Enter the wallet name to use for mining: ").strip()
        config["wallet_name"] = wallet_name

    # Save updated config
    with open(config_file, "w") as f:
        json.dump(config, f, indent=4)

    server_url = f"http://{server_ip}:{server_port}/submit_tx"
    print(f"\nUsing validator server at: {server_url}")

    return server_ip, server_port, server_url, wallet_name

# --------------------
# Main Menu
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
    global wallet_name, private_key_path, public_key_path
    
    while True:
        print("="*24)
        print(" " * 8 + "Config")
        print("="*24)
        print("1. Update Config")
        print("2. View Config")
        print("3. Back")
        print() #skip line
        choice = input("Select an option: ").strip()

        if choice == "1":
            # Update server IP/port using the config
            server_ip, server_port, server_url, wallet_name = load_or_init_config(
            CONFIG_FILE,
            force_edit=True
            )
            # Try to reload wallet immediately after config change
            global private_key, public_key_pem, private_key_path, public_key_path
            private_key, public_key_pem, private_key_path, public_key_path = load_wallet(wallet_name)

        elif choice == "2":
            
            # Display wallet info   
            print() #skip line
            print("-"*60)
            print(f"Using validator server at: {server_url}")
            print(f"Wallet name: {wallet_name}")
            print("-"*60)
            
            print() #skip line

        elif choice == "3":
            # Return to main menu
            print() #skip line
            return
        else:
            # Invalid choice handler
            print("\nInvalid option, please try again.")

def main_menu():
    """
    Display a menu for the user before mining starts.
    Options:
        1. Start Mining
        2. Edit/View Config
        3. Exit
    """
    global server_ip, server_port, server_url
    global wallet_name, private_key_path, public_key_path
    
    while True:
        print("="*24)
        print(" " * 8 + "Menu")
        print("="*24)
        print("1. Start Mining")
        print("2. Edit/View Config")
        print("3. Exit program")
        print() #skip line
        choice = input("Select an option: ").strip()

        if choice == "1":
            # Start mining (exit menu)
            if private_key is None:           
                    print("\nCannot start mining: wallet not loaded. Please update your wallet in the config menu first.\n")
                    continue  # force them to stay in main menu
            
            print("\nStarting mining...")
            break

        elif choice == "2":
            # Optional Config Menu
            print() #skip line
            sub_menu() 

        elif choice == "3":
            # Exit program gracefully
            print("\nExiting program")
            exit(0)

        else:
            # Invalid choice handler
            print("Invalid option, please try again.")

# 1. Load or initialize config
server_ip, server_port, server_url, wallet_name = load_or_init_config(CONFIG_FILE)

# 2. Load wallet
private_key, public_key_pem, private_key_path, public_key_path = load_wallet(wallet_name)


main_menu()
"""
# 3. Optional Config Menu
open_menu = input("Edit/View Config? (y/N): ").strip().lower()
if open_menu == "y":
    main_menu()
 """

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
            
             # sign bytes from above using Pi's private key
             # resulting in a long sequence of pytes that proves the message came from this device (Pi)
            signature_bytes = private_key.sign(message) 
           
           # convert bytes into base64 so they can be placed in the JSON payload safely
           # This is not encryption, it is just making it so that it can be printable in the end
            signature_b64 = base64.b64encode(signature_bytes).decode()  

            # -----------------------------------------------------------------
            # Build the JSON message payload to send to the server (validator)
            # -----------------------------------------------------------------
            tx_payload = {
                "type": "MINT", #transaction type is always MINT (creating coins)
                "from_addr": public_key_pem,  # public key of the device (signer)
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
                print("Error sending to validator:", e)
                print("Details:", e)
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
