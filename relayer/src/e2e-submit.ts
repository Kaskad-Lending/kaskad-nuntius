/**
 * E2E helper: reads signed prices from stdin (JSON), verifies sigs,
 * submits to on-chain oracle via ethers.js. Exits 0 if >= 2 submitted.
 */
import { ethers } from "ethers";
import { KaskadPriceOracle__factory } from "./types/contracts/factories/KaskadPriceOracle__factory.js";

const rpcUrl = process.env.RPC_URL!;
const oracleAddr = process.env.ORACLE_ADDRESS!;
const privateKey = process.env.PRIVATE_KEY!;

// Read pull API response from stdin
let input = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) {
  input += chunk;
}

const pullData = JSON.parse(input);
const prices = pullData.prices || [];
const enclaveSigner = pullData.signer;

console.log(`  Relayer received ${prices.length} prices from signer ${enclaveSigner}`);

const provider = new ethers.JsonRpcProvider(rpcUrl);
const wallet = new ethers.Wallet(privateKey, provider);
const oracle = KaskadPriceOracle__factory.connect(oracleAddr, wallet);

console.log(`  Relayer wallet: ${wallet.address}`);

let submitted = 0;
let nonce = await wallet.getNonce("latest");

for (const p of prices) {
  // H-2: Verify EIP-191 signature locally
  const payload = ethers.solidityPacked(
    ["bytes32", "uint256", "uint256", "uint8", "bytes32"],
    [p.asset_id, BigInt(p.price), BigInt(p.timestamp), p.num_sources, p.sources_hash]
  );
  const msgHash = ethers.keccak256(payload);
  const ethHash = ethers.hashMessage(ethers.getBytes(msgHash));
  const recovered = ethers.recoverAddress(ethHash, p.signature);

  if (recovered.toLowerCase() !== enclaveSigner.toLowerCase()) {
    console.log(`  ✗ Sig mismatch for ${p.asset_symbol}: recovered=${recovered}`);
    continue;
  }

  // M-4: Skip if numSources < 3
  if (p.num_sources < 3) {
    console.log(`  ⚠ Skipping ${p.asset_symbol} — only ${p.num_sources} sources`);
    continue;
  }

  try {
    const tx = await oracle.updatePrice(
      p.asset_id,
      BigInt(p.price),
      BigInt(p.timestamp),
      p.num_sources,
      p.sources_hash,
      p.signature,
      { nonce: nonce++ }
    );
    const receipt = await tx.wait();
    console.log(`  ✓ ${p.asset_symbol} — tx: ${receipt!.hash.slice(0, 18)}...`);
    submitted++;
  } catch (e: any) {
    console.log(`  ⚠ ${p.asset_symbol} — revert: ${e.shortMessage || e.message}`);
  }
}

console.log(`  Submitted: ${submitted} / ${prices.length} assets`);
process.exit(submitted >= 2 ? 0 : 1);
