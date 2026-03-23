import os
import sys
import json
import time
import subprocess
import urllib.request

RPC = "https://galleon-testnet.igralabs.com:8545"
KEY = "0x74d8f8f7abad7f654f9a365ba6dd7192a709d8df0e83a735e1a20c99f1febb2d"
GAS_PRICE = "2002gwei"

# Get current nonce so we can track exactly what mines
def get_nonce():
    cmd = ["cast", "nonce", "0xe92cf3419E91EDBeAc9DD8eAC7728Df5DCe57A52", "--rpc-url", RPC]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return int(result.stdout.strip())

def test_sequencer_size(size):
    hex_size = f"{size:06x}"
    # init code that returns 0 bytes
    padding_len = size - 5
    if padding_len < 0: padding_len = 0
    init_code = "0x60006000f3" + ("00" * padding_len)
    
    start_nonce = get_nonce()
    
    cmd = ["cast", "send", "--legacy", "--rpc-url", RPC, "--private-key", KEY, "--gas-price", GAS_PRICE, "--gas-limit", "300000", "--create", init_code]
    print(f"  Sending tx with init_code size: {size} bytes...", end=" ", flush=True)
    try:
        # Give it 20 seconds. If Galleon drops it, it never mines.
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if result.returncode == 0:
            print("MINED!")
            return True
        else:
            print(f"FAILED TO MINE! Reverted or Error. {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        # Check if nonce incremented
        end_nonce = get_nonce()
        if end_nonce > start_nonce:
            print("MINED (but cast timed out)!")
            return True
        print("SILENTLY DROPPED (Timeout)!")
        return False

print("Starting binary search for Galleon Sequencer transaction size limit...")
low = 100
high = 30000
best = low

# we can skip smaller boundaries to save time. We know 0-value 0-data works.
while low <= high:
    mid = (low + high) // 2
    succ = test_sequencer_size(mid)
    
    if succ:
        best = mid
        low = mid + 1
    else:
        high = mid - 1

print(f"\n== Maximum Sequencer Transaction Size on Galleon is exactly: {best} bytes ==")
