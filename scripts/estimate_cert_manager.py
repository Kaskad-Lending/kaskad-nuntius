import json
import urllib.request
import sys

def get_bytecode(contract_path):
    with open(f"contracts/out/{contract_path}") as f:
        data = json.load(f)
        return data["bytecode"]["object"]

bytecode = get_bytecode("CertManager.sol/CertManager.json")

payload = {
    "jsonrpc": "2.0",
    "method": "eth_estimateGas",
    "params": [{"data": bytecode}],
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
        print(f"FAILED to estimate CertManager: {result['error']}")
    else:
        print(f"SUCCESS! Gas estimate: {int(result['result'], 16)}")
except Exception as e:
    print(f"HTTP Error: {e}")
