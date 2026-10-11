const assert = require('assert');
const { traceAES128, keyExpansion, SBOX } = require('./aes-engine.js');

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

function runAllTests() {
  console.log("==========================================");
  console.log("   AES CRYPTO LAB - COMPREHENSIVE VERIFICATION");
  console.log("==========================================");

  // 1. Known-Answer Test (FIPS-197 Standard)
  console.log("\n[1] Running AES-128 FIPS-197 Known Answer Test (KAT)...");
  const keyHex = "000102030405060708090a0b0c0d0e0f";
  const plainHex = "00112233445566778899aabbccddeeff";
  const expectedCipher = "69c4e0d86a7b0430d8cdb78070b4c55a";

  const trace = traceAES128(hexToBytes(plainHex), hexToBytes(keyHex));
  const actualCipher = bytesToHex(trace.finalCiphertext);

  assert.strictEqual(actualCipher, expectedCipher, "KAT Ciphertext must match FIPS-197 test vector");
  console.log("  ✓ Key:            ", keyHex);
  console.log("  ✓ Plaintext:      ", plainHex);
  console.log("  ✓ Expected Cipher:", expectedCipher);
  console.log("  ✓ Computed Cipher:", actualCipher);
  console.log("  ✓ FIPS-197 Known Answer Test PASSED!");

  // 2. Round Structure & Step Count Verification
  console.log("\n[2] Verifying Round Structure & Transformations...");
  assert.strictEqual(trace.steps.length, 40, "Total steps must be 40 (1 pre-round + 9*4 main rounds + 3 round 10 steps)");
  
  const round10Steps = trace.steps.filter(s => s.round === 10);
  assert.strictEqual(round10Steps.length, 3, "Round 10 must contain exactly 3 operations (no MixColumns)");
  assert.deepStrictEqual(
    round10Steps.map(s => s.op),
    ["SubBytes", "ShiftRows", "AddRoundKey"],
    "Round 10 must be SubBytes -> ShiftRows -> AddRoundKey (MixColumns omitted)"
  );
  console.log("  ✓ Step count verified (40 total discrete transformations).");
  console.log("  ✓ Round 10 structure verified: MixColumns is correctly omitted.");

  // 3. Web Crypto AES-GCM (128 & 256) Functional & Security Tests
  console.log("\n[3] Testing Web Crypto AES-GCM Subsystem...");

  async function testGCM() {
    const { subtle } = crypto;
    const testPlain = "College Cryptography and Network Security Project!";
    const testPlainBytes = new TextEncoder().encode(testPlain);

    for (const bits of [128, 256]) {
      const keyBytes = crypto.getRandomValues(new Uint8Array(bits / 8));
      const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce

      const key = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
      const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, testPlainBytes);

      // Decrypt
      const decrypted = await subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, ciphertext);
      const recovered = new TextDecoder().decode(decrypted);
      assert.strictEqual(recovered, testPlain, `AES-${bits}-GCM recovered text must match original`);
      console.log(`  ✓ AES-${bits}-GCM: Encrypt -> Decrypt recovered original plaintext.`);

      // Wrong key rejection
      const wrongKeyBytes = crypto.getRandomValues(new Uint8Array(bits / 8));
      const wrongKey = await subtle.importKey("raw", wrongKeyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
      let rejectedWrongKey = false;
      try {
        await subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, wrongKey, ciphertext);
      } catch (e) {
        rejectedWrongKey = true;
      }
      assert.strictEqual(rejectedWrongKey, true, `AES-${bits}-GCM must reject wrong key`);
      console.log(`  ✓ AES-${bits}-GCM: Rejected wrong decryption key.`);

      // Tampered ciphertext rejection
      const tamperedCipher = new Uint8Array(ciphertext);
      tamperedCipher[0] ^= 0x55; // alter first byte
      let rejectedTamper = false;
      try {
        await subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, tamperedCipher);
      } catch(e) {
        rejectedTamper = true;
      }
      assert.strictEqual(rejectedTamper, true, `AES-${bits}-GCM must reject modified ciphertext`);
      console.log(`  ✓ AES-${bits}-GCM: Rejected corrupted/tampered ciphertext.`);

      // Tampered tag rejection
      const tamperedTag = new Uint8Array(ciphertext);
      tamperedTag[tamperedTag.length - 1] ^= 0x01; // flip bit in 16-byte authentication tag
      let rejectedTag = false;
      try {
        await subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, tamperedTag);
      } catch(e) {
        rejectedTag = true;
      }
      assert.strictEqual(rejectedTag, true, `AES-${bits}-GCM must reject modified authentication tag`);
      console.log(`  ✓ AES-${bits}-GCM: Rejected modified authentication tag.`);
    }

    console.log("\n==========================================");
    console.log("   ALL SYSTEM AND CRYPTO TESTS PASSED!    ");
    console.log("==========================================");
  }

  return testGCM();
}

runAllTests().catch(err => {
  console.error("Verification failed:", err);
  process.exit(1);
});
