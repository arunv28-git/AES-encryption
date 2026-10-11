const { traceAES128 } = require('./aes-engine.js');

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

console.log("=== AES-128 FIPS-197 Standard Known-Answer Test ===");

const keyHex = "000102030405060708090a0b0c0d0e0f";
const plainHex = "00112233445566778899aabbccddeeff";
const expectedCipherHex = "69c4e0d86a7b0430d8cdb78070b4c55a";

const trace = traceAES128(hexToBytes(plainHex), hexToBytes(keyHex));
const actualCipherHex = bytesToHex(trace.finalCiphertext);

console.log("Key:             ", keyHex);
console.log("Plaintext:       ", plainHex);
console.log("Expected Cipher: ", expectedCipherHex);
console.log("Actual Cipher:   ", actualCipherHex);
console.log("Total Steps:     ", trace.steps.length); // 1 + 9*4 + 3 = 40 steps

if (actualCipherHex === expectedCipherHex) {
  console.log(">>> [SUCCESS] Known Answer Test PASSED perfectly! <<<");
} else {
  console.error(">>> [FAIL] Known Answer Test MISMATCH! <<<");
  process.exit(1);
}

// Test WebCrypto AES-GCM
async function testWebCrypto() {
  console.log("\n=== Testing Web Crypto AES-GCM (128 & 256) ===");
  const { subtle } = crypto;

  // 128-GCM
  const rawKey128 = crypto.getRandomValues(new Uint8Array(16));
  const iv128 = crypto.getRandomValues(new Uint8Array(12));
  const msg = new TextEncoder().encode("Hello AES-GCM WebCrypto Test!");
  
  const k128 = await subtle.importKey("raw", rawKey128, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const encrypted128 = await subtle.encrypt({ name: "AES-GCM", iv: iv128, tagLength: 128 }, k128, msg);
  const decrypted128 = await subtle.decrypt({ name: "AES-GCM", iv: iv128, tagLength: 128 }, k128, encrypted128);
  const recovered128 = new TextDecoder().decode(decrypted128);
  console.log("AES-128-GCM Recovered:", recovered128);
  if (recovered128 !== "Hello AES-GCM WebCrypto Test!") throw new Error("128 Decrypt failed");

  // Tamper test
  const tampered = new Uint8Array(encrypted128);
  tampered[tampered.length - 1] ^= 0x01; // flip last byte of tag
  let caught = false;
  try {
    await subtle.decrypt({ name: "AES-GCM", iv: iv128, tagLength: 128 }, k128, tampered);
  } catch(e) {
    caught = true;
    console.log("Tampered tag correctly rejected:", e.message);
  }
  if (!caught) throw new Error("Tampered tag was not rejected!");

  // 256-GCM
  const rawKey256 = crypto.getRandomValues(new Uint8Array(32));
  const iv256 = crypto.getRandomValues(new Uint8Array(12));
  const k256 = await subtle.importKey("raw", rawKey256, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const encrypted256 = await subtle.encrypt({ name: "AES-GCM", iv: iv256, tagLength: 128 }, k256, msg);
  const decrypted256 = await subtle.decrypt({ name: "AES-GCM", iv: iv256, tagLength: 128 }, k256, encrypted256);
  const recovered256 = new TextDecoder().decode(decrypted256);
  console.log("AES-256-GCM Recovered:", recovered256);
  if (recovered256 !== "Hello AES-GCM WebCrypto Test!") throw new Error("256 Decrypt failed");

  console.log(">>> [SUCCESS] WebCrypto AES-GCM tests all PASSED! <<<");
}

testWebCrypto().catch(err => {
  console.error("Test error:", err);
  process.exit(1);
});
