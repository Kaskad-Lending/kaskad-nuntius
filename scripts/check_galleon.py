import json
import urllib.request

payload = {
    "jsonrpc": "2.0",
    "method": "eth_getBlockByNumber",
    "params": ["latest", False],
    "id": 1
}

req = urllib.request.Request(
    "https://galleon-testnet.igralabs.com:8545",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"}
)

response = urllib.request.urlopen(req)
result = json.loads(response.read())

gas_limit_hex = result['result']['gasLimit']
gas_limit = int(gas_limit_hex, 16)
print(f"Galleon Testnet Block Gas Limit: {gas_limit}")
