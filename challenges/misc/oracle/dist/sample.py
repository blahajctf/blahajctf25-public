from pwn import *
import json

HOST = 'localhost'
PORT = 1337
DECIMALS = 10**18

# The contract addresses and player public address are fixed for this challenge

def send_tx(p, tx_data):
    """
    Helper function to send a transaction and get the full JSON response.
    It reads until a newline character, which the server sends to delimit messages.
    """
    if not p.connected():
        log.error("Connection lost.")
        return None

    p.sendlineafter(b'>', json.dumps(tx_data).encode())
    
    try:
        response_bytes = p.recvline().strip()
        if not response_bytes:
            log.warning("Received an empty response from the server.")
            return None
        return json.loads(response_bytes)
    except (EOFError, ConnectionResetError):
        log.error("Connection closed by the server while waiting for a response.")
        return None
    except json.JSONDecodeError as e:
        log.error(f"Failed to decode JSON from server: {e}")
        log.info(f"Received raw data: {response_bytes}")
        return None

def main():
    p = remote(HOST, PORT)
    # Get your balance
    player_balance_tx = {
        "user": "0x38Dc745781c2C5a16a5d1870876ABFbD1Cec5ac2",
        "calls": [
            {"function": "get_user_balance", "args": ["0x38Dc745781c2C5a16a5d1870876ABFbD1Cec5ac2"]}
        ]
    }
    response = send_tx(p, player_balance_tx)
    print(response)

    # Get contract balances
    dex_balance_tx = {
        "user": "0x38Dc745781c2C5a16a5d1870876ABFbD1Cec5ac2",
        "calls": [
            {"function": "get_contract_balances", "args": ["0x3a8e9A27AbC7cb3F71691c1B5bf216e72A5D0283"]}
        ]
    }
    response = send_tx(p, dex_balance_tx)
    print(response)
    
    # Contract interaction example
    usdc_to_swap = 100 * DECIMALS

    swap_tx = {
        "user": "0x38Dc745781c2C5a16a5d1870876ABFbD1Cec5ac2",
        "calls": [
            {
                "address": "0x3a8e9A27AbC7cb3F71691c1B5bf216e72A5D0283",
                "function": "swap",
                "args": ["USDC", "BLAHAJ", usdc_to_swap] # from, to, amount
            }
        ]
    }
    response = send_tx(p, swap_tx)
    print(response)

    blahaj_to_swap = 100 * DECIMALS
    swap_tx = {
        "user": "0x38Dc745781c2C5a16a5d1870876ABFbD1Cec5ac2",
        "calls": [
            {
                "address": "0x3a8e9A27AbC7cb3F71691c1B5bf216e72A5D0283",
                "function": "swap",
                "args": ["BLAHAJ", "USDC", blahaj_to_swap] # from, to, amount
            }
        ]
    }
    response = send_tx(p, swap_tx)
    print(response)

    p.close()

if __name__ == "__main__":
    main()