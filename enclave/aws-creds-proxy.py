#!/usr/bin/env python3
"""AWS IAM credentials → enclave bridge (host-side).

Runs on the EC2 host (the same box as `pull_api.py`). Listens on
VSOCK port 5002 for connections from the enclave; on each accepted
connection it reads the EC2 instance role's credentials from IMDSv2
and writes them back as a length-prefixed JSON blob. The enclave
uses these credentials to SigV4-sign KMS / S3 calls when sealing /
unsealing its signing key.

The host already has these credentials by virtue of the instance
profile, so this proxy doesn't grant the enclave anything extra
that the host doesn't already have. The enclave's KMS key policy
gates `kms:Decrypt` on the attestation document's PCR0, so even
though the host could *also* call kms:Encrypt with these creds,
it can't decrypt the sealed blob without producing a valid
attestation — which only the running enclave can.

Wire format (per accepted connection):
    enclave → host: 1 byte (any value, ignored — connection ping)
    host → enclave: [4 bytes BE length][JSON body]

JSON body matches IMDSv2 schema:
    {"AccessKeyId":"...", "SecretAccessKey":"...",
     "Token":"...", "Expiration":"..."}
"""
import json
import socket
import struct
import sys
import time
import urllib.request

AF_VSOCK = 40
LISTEN_PORT = 5002
IMDS_HOST = "http://169.254.169.254"
TOKEN_TTL = 21600  # 6h


def fetch_creds():
    """Two-leg IMDSv2: PUT for token, GET role+creds with token header."""
    token_req = urllib.request.Request(
        f"{IMDS_HOST}/latest/api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": str(TOKEN_TTL)},
    )
    with urllib.request.urlopen(token_req, timeout=2) as r:
        token = r.read().decode().strip()

    role_req = urllib.request.Request(
        f"{IMDS_HOST}/latest/meta-data/iam/security-credentials/",
        headers={"X-aws-ec2-metadata-token": token},
    )
    with urllib.request.urlopen(role_req, timeout=2) as r:
        role = r.read().decode().strip()

    creds_req = urllib.request.Request(
        f"{IMDS_HOST}/latest/meta-data/iam/security-credentials/{role}",
        headers={"X-aws-ec2-metadata-token": token},
    )
    with urllib.request.urlopen(creds_req, timeout=2) as r:
        return json.loads(r.read().decode())


def serve():
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    s.bind((-1, LISTEN_PORT))   # -1 = VMADDR_CID_ANY
    s.listen(8)
    print(f"[creds-proxy] listening on VSOCK port {LISTEN_PORT}", flush=True)
    while True:
        try:
            conn, peer = s.accept()
        except OSError as e:
            print(f"[creds-proxy] accept failed: {e}", file=sys.stderr, flush=True)
            time.sleep(1)
            continue
        try:
            # Drain the 1-byte ping so the enclave knows it's connected.
            conn.recv(1)
            creds = fetch_creds()
            body = json.dumps(creds).encode()
            conn.sendall(struct.pack(">I", len(body)))
            conn.sendall(body)
        except Exception as e:
            print(f"[creds-proxy] error on conn from {peer}: {e}",
                  file=sys.stderr, flush=True)
        finally:
            try:
                conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    serve()
