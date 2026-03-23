import os
import sys
import json
import time
import subprocess
import urllib.request

RPC = "https://galleon-testnet.igralabs.com:8545"
KEY = "0x74d8f8f7abad7f654f9a365ba6dd7192a709d8df0e83a735e1a20c99f1febb2d"
GAS_PRICE = "2000gwei"

def run_cast_create(bytecode, args=None):
    cmd = ["cast", "send", "--legacy", "--rpc-url", RPC, "--private-key", KEY, "--gas-price", GAS_PRICE, "--gas-limit", "30000000", "--create", bytecode]
    if args:
        cmd.extend(args)
    print(f"Running: {' '.join(cmd[:9])} ...")
    try:
        # We don't want to wait forever if Galleon silently drops it
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.startswith("contractAddress"):
                    addr = line.split()[1].strip()
                    print(f"--> Deployed at {addr}")
                    return addr
        print(f"Failed. STDOUT: {result.stdout}\nSTDERR: {result.stderr}")
        return None
    except subprocess.TimeoutExpired:
        print("Timeout! Transaction was likely silently dropped by Galleon.")
        return None

def run_cast_call(to, sig, *args):
    cmd = ["cast", "send", "--legacy", "--rpc-url", RPC, "--private-key", KEY, "--gas-price", GAS_PRICE, "--gas-limit", "30000000", to, sig] + list(args)
    print(f"Running: {' '.join(cmd[:11])} ...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("--> Success!")
            return True
        print(f"Failed. STDOUT: {result.stdout}\nSTDERR: {result.stderr}")
        return False
    except subprocess.TimeoutExpired:
        print("Timeout! Transaction was likely silently dropped by Galleon.")
        return False

def get_bytecode(contract_path):
    with open(f"contracts/out/{contract_path}") as f:
        data = json.load(f)
        return data["bytecode"]["object"]

print("1. Deploying CertManager...")
cert_manager_bytecode = get_bytecode("CertManager.sol/CertManager.json")
cert_manager_addr = None
while not cert_manager_addr:
    cert_manager_addr = run_cast_create(cert_manager_bytecode)
    if not cert_manager_addr:
        print("Retrying CertManager deployment...")

print("2. Initializing CertManager...")
success = False
while not success:
    success = run_cast_call(cert_manager_addr, "initialize()")
    if not success:
        print("Retrying CertManager initialization...")

print("3. Deploying NitroProver...")
prover_bytecode = get_bytecode("NitroProver.sol/NitroProver.json")
prover_addr = None
while not prover_addr:
    prover_addr = run_cast_create(prover_bytecode, ["constructor(address)", cert_manager_addr])
    if not prover_addr:
        print("Retrying NitroProver deployment...")

print("4. Deploying NitroAttestationVerifier...")
verifier_bytecode = get_bytecode("NitroAttestationVerifier.sol/NitroAttestationVerifier.json")
verifier_addr = None
while not verifier_addr:
    verifier_addr = run_cast_create(verifier_bytecode, ["constructor(address,uint256)", prover_addr, "31536000"])
    if not verifier_addr:
        print("Retrying NitroAttestationVerifier deployment...")

print("5. Getting Attestation Doc from Prod ALB...")
resp = urllib.request.urlopen("http://kaskad-oracle-alb-670133639.us-east-1.elb.amazonaws.com/attestation")
doc_hex = json.loads(resp.read())["attestation_doc"]

print("6. Calling verifyCerts...")
success = False
while not success:
    success = run_cast_call(verifier_addr, "verifyCerts(bytes)", "0x" + doc_hex)
    if not success:
        print("Retrying verifyCerts...")

print("7. Extracting PCR0...")
result = subprocess.run(["cast", "call", "--rpc-url", RPC, verifier_addr, "verifyAttestation(bytes)(bool,bytes32,address)", "0x" + doc_hex], capture_output=True, text=True)
pcr0 = result.stdout.strip().split('\n')[1]
print(f"Extracted PCR0: {pcr0}")

print("8. Deploying KaskadPriceOracle...")
oracle_bytecode = get_bytecode("KaskadPriceOracle.sol/KaskadPriceOracle.json")
oracle_addr = None
while not oracle_addr:
    oracle_addr = run_cast_create(oracle_bytecode, ["constructor(bytes32,address)", pcr0, verifier_addr])
    if not oracle_addr:
        print("Retrying KaskadPriceOracle deployment...")

print("9. Registering Enclave...")
success = False
while not success:
    success = run_cast_call(oracle_addr, "registerEnclave(bytes)", "0x" + doc_hex)
    if not success:
        print("Retrying registerEnclave...")

print(f"\nSUCCESS! Oracle successfully deployed on Galleon Testnet at {oracle_addr}")
