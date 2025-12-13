
 <p align="center">
  <img src="CoolCoinLogo2.png" alt="CoolCoin thumbnail" width="400">
</p>

---

Cool-Coin is a proof-of-concept Decentralized Physical Infrastructure Network (DePIN).

## Core Architecture

### 1. Physical Infrastructure (Miner / Raspberry Pi)
- Collects temperature, pressure, humidity via BME280 sensor.
- Signs each reading and submits a MINT transaction to earn 1 Cool-Coin.

### 2. Validator (Server)
- FastAPI server that processes transactions.
- Verifies signatures, maintains blockchain ledger, manages mempool.

### 3. Client Interfaces
- **Dashboard**: real-time web interface showing balances, latest sensor readings, and transaction history.
- **Wallet Scripts**: Python scripts for key generation and sending TRANSFER transactions.

## Project Files

**Main Components:**
- `server.py`: Validator node, verifies transactions, maintains blockchain/mempool.
- `cool_coin_miner.py`: Miner script, reads sensor data, signs, and submits MINT transactions.
- `cool_coin_dashboard.HTML`: Web dashboard fetching live data from the validator.

**Wallet Management / Demo Scripts:**
- `wallet_generation.py`: Generates new Ed25519 public/private key pairs.
- `transfer.py`: Sends signed TRANSFER transactions from one wallet to another.

**Key Files:**
- `miner_wallet.pem` / `miner_wallet.pub`: Miner private/public key pair (Wallet 1).
- `new_wallet.pem` / `new_wallet.pub`: Demo client wallet (Wallet 2).

**Misc Files:**
- `blockchain.json`: Ledger of confirmed transactions. Allows blockchain to be saved across server sessions (unused).
- `mempool.json`: Pending transactions awaiting confirmation. Allows mempool to be saved across server sessions (unused).

## Setup

### Prerequisites
- **Validator Host:** machine to run `server.py`.
- **Miner Host:** Raspberry Pi with Python and BME280 sensor.
- **Network:** All devices on same local network; firewall allows port 8000.

### 1. Validator Setup (On Laptop)
- Install dependencies:
   ```bash
   pip install fastapi uvicorn pydantic cryptography requests python-multipart
- Run server:
  ```bash
  uvicorn server:app --reload --host 0.0.0.0 --port 8000
- Run ipconfig to find server IP

### 2. Miner Setup (On Pi)
- Install dependencies:
  ```bash
  pip install adafruit-circuitpython-bme280 requests cryptography
- Generate the miner's wallet:
  ```bash
   openssl genpkey -algorithm Ed25519 -out miner_wallet.pem
   openssl pkey -in miner_wallet.pem -pubout -out miner_wallet.pub
- Update server_url in cool_coin_miner.py to server IP.
- Run miner:
  ```bash
  python3 cool_coin_miner.py

### 3. Dashboard and Second Wallet
- Open cool_coin_dashboard.HTML in browser.
- Update fetch calls to validator IP.
- Generate Wallet 2:
  ```bash
  python3 wallet_generation.py
- Test transfer:
  ```bash
  python3 transfer.py




