#!/usr/bin/env python3
"""Publish the oracle enclave's NSM attestation to S3 for on-chain registration.

Runs on the host after the oracle enclave (CID 16) boots. Polls the keyex
control channel (VSOCK 5005) for `get_attestation`, then uploads the reply
(a public COSE doc + signer + PCR0, no secret) to s3://<bucket>/genesis/.
The doc is what `RegisterEnclave` feeds on-chain; the enclave never exposes the
key. Read-only against the enclave; safe on every boot.
"""

import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.request

AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
MAX_FRAME = 64 * 1024
POLL_DEADLINE_S = 900
POLL_INTERVAL_S = 5
CALL_TIMEOUT_S = 15

_log_lines: list[str] = []


def log(msg: str) -> None:
    line = f"[genesis-capture] {msg}"
    print(line, flush=True)
    _log_lines.append(line)


def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def vsock_call(cid: int, port: int, req: dict) -> dict:
    """One framed request/response over VSOCK (4-byte BE length prefix)."""
    sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    sock.settimeout(CALL_TIMEOUT_S)
    try:
        sock.connect((cid, port))
        body = json.dumps(req).encode()
        sock.sendall(struct.pack(">I", len(body)) + body)
        n = struct.unpack(">I", _recvn(sock, 4))[0]
        if n == 0 or n > MAX_FRAME:
            raise ValueError(f"bad response frame length {n}")
        return json.loads(_recvn(sock, n))
    finally:
        sock.close()


def imds_instance_id(region: str) -> str:
    token = urllib.request.urlopen(
        urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        ),
        timeout=5,
    ).read().decode()
    return urllib.request.urlopen(
        urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/instance-id",
            headers={"X-aws-ec2-metadata-token": token},
        ),
        timeout=5,
    ).read().decode().strip()


def s3_put(data: bytes, bucket: str, key: str, region: str) -> None:
    subprocess.run(
        ["aws", "s3", "cp", "-", f"s3://{bucket}/{key}", "--region", region],
        input=data, check=True,
    )


def valid_attestation(reply: dict) -> bool:
    att, signer, pcr0 = reply.get("attestation"), reply.get("signer"), reply.get("pcr0")
    return (
        isinstance(att, str) and att.startswith("0x") and len(att) > 2
        and isinstance(signer, str) and signer.startswith("0x") and len(signer) == 42
        and isinstance(pcr0, str) and len(pcr0) == 98  # 0x + 48 bytes
    )


def main() -> int:
    bucket = os.environ["KASKAD_EIF_BUCKET"]
    region = os.environ.get("KASKAD_AWS_REGION", "us-east-1")
    cid = int(os.environ.get("KASKAD_ORACLE_CID", "16"))
    port = int(os.environ.get("KASKAD_CONTROL_PORT", "5005"))

    try:
        iid = imds_instance_id(region)
    except Exception as e:  # IMDS should always answer on a real instance
        log(f"FATAL: cannot read instance-id from IMDS: {e}")
        return 1
    log(f"instance={iid} oracle_cid={cid} control_port={port} bucket={bucket}")

    deadline = time.monotonic() + POLL_DEADLINE_S
    reply = None
    while time.monotonic() < deadline:
        try:
            h = vsock_call(cid, port, {"method": "keyex_health"})
            log(f"health: state={h.get('state')} source={h.get('source')} signer={h.get('signer')}")
        except Exception as e:
            log(f"control not up yet: {e}")
            time.sleep(POLL_INTERVAL_S)
            continue
        try:
            r = vsock_call(cid, port, {"method": "get_attestation"})
        except Exception as e:
            log(f"get_attestation call failed: {e}")
            time.sleep(POLL_INTERVAL_S)
            continue
        if valid_attestation(r):
            reply = r
            break
        log(f"attestation not ready: {json.dumps(r)}")
        time.sleep(POLL_INTERVAL_S)

    try:
        if reply is None:
            log("FATAL: attestation not available before deadline")
            return 1
        log(f"captured attestation: signer={reply['signer']} pcr0={reply['pcr0']} bytes={len(reply['attestation'])//2 - 1}")
        blob = json.dumps({**reply, "instanceId": iid}, separators=(",", ":")).encode()
        s3_put(blob, bucket, f"genesis/{iid}.json", region)
        s3_put(blob, bucket, "genesis/latest.json", region)
        log(f"published s3://{bucket}/genesis/{iid}.json + genesis/latest.json")
        return 0
    finally:
        try:
            s3_put(("\n".join(_log_lines) + "\n").encode(), bucket, f"genesis/{iid}.log", region)
        except Exception as e:
            print(f"[genesis-capture] WARN: log upload failed: {e}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
