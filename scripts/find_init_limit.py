import json
import urllib.request
import sys

def test_init_size(size):
    # We want the transaction data to be `size` bytes long.
    # We create a valid but pointless deploy transaction returning 0 bytes.
    # 0x60006000f3 returns 0 bytes. Total 5 bytes.
    # The rest is just padding (e.g. 00..00)
    padding_len = size - 5
    if padding_len < 0: padding_len = 0
    init_code = "0x60006000f3" + ("00" * padding_len)
    
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
        response = urllib.request.urlopen(req, timeout=10)
        result = json.loads(response.read())
        if 'error' in result:
            return False, result['error'].get('message', '')
        return True, result.get('result', '')
    except Exception as e:
        return False, str(e)

print("Starting binary search for INIT CODE SIZE...")
low = 100
high = 50000
best = low

while low <= high:
    mid = (low + high) // 2
    succ, msg = test_init_size(mid)
    
    if succ:
        print(f"Testing {mid} bytes: SUCCESS")
        best = mid
        low = mid + 1
    else:
        print(f"Testing {mid} bytes: FAILED ({msg})")
        high = mid - 1

print(f"== Maximum INIT CODE Size on Galleon is exactly: {best} bytes ==")
