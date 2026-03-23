import json
import urllib.request
import sys

def test_size(size):
    hex_size = f"{size:06x}"
    # 0x62 (push3 size) 80 (dup1) 60 0c (push1 12) 60 00 (push1 0) 39 (codecopy) 60 00 (push1 0) f3 (return)
    init_code = f"0x62{hex_size}80600c6000396000f3" + ("00" * size)
    
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_estimateGas",
        "params": [{"data": init_code}],
        "id": 1
    }
    
    req = urllib.request.Request(
        "https://galleon-testnet.igralabs.com:8545",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}
    )
    
    try:
        response = urllib.request.urlopen(req)
        result = json.loads(response.read())
        if 'error' in result:
            return False, result['error'].get('message', '')
        return True, result.get('result', '')
    except Exception as e:
        return False, str(e)

print(f"Testing 24576 bytes (Standard EIP-170)...")
succ, msg = test_size(24576)
print(f"Standard EIP-170 limit (24576): {'Success' if succ else 'Failed'}, Msg: {msg}")

low = 100
high = 30000
best = low

print(f"Starting binary search between {low} and {high} bytes...")
while low <= high:
    mid = (low + high) // 2
    succ, msg = test_size(mid)
    
    if succ:
        print(f"Testing {mid}: SUCCESS")
        best = mid
        low = mid + 1
    else:
        print(f"Testing {mid}: FAILED ({msg})")
        high = mid - 1

print(f"== Maximum Contract Size on Galleon is exactly: {best} bytes ==")
