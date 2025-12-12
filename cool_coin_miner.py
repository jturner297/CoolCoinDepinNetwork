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


# ----------------------------------------------------------
# Load the wallet keys
# 
# These come from:
#   Generating private key with this command: 
#       openssl genpkey -algorithm Ed25519 -out miner_wallet.pem
#   
#   Extracting matching public key with this command: 
#       openssl pkey -in miner_wallet.pem -pubout -out miner_wallet.pub
#
#   PEM formatting was used in keys because it works perfect with
#   Python's cryptography library
# ----------------------------------------------------------


 # load private key
with open("miner_wallet.pem", "rb") as f:          # open the private key file
    private_key = serialization.load_pem_private_key(
        f.read(),                               # read the file contents
        password=None                           # no password on the key
    )

# load public key
with open("miner_wallet.pub", "rb") as f:          # open the public key file
    public_key_pem = f.read().decode().strip() # store the text version for JSON output (turn into normat text bytes)


# ----------------------------------------------------------
# Validator server
# ----------------------------------------------------------
server_url = "http://192.168.137.2:8000/submit_tx"  # FastAPI endpoint (used to submit the transaction)



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
