// AES-128 Reference Engine & Known Answer Test (FIPS-197)

// Rijndael S-Box
const SBOX = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5e, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

// Round constant Rcon
const RCON = [
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
];

// GF(2^8) xtime: multiplication by 2 modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
function xtime(b) {
  return ((b << 1) ^ (((b >> 7) & 1) * 0x11b)) & 0xff;
}

// Key Expansion for AES-128: 16 bytes key -> 11 round keys of 16 bytes (44 32-bit words)
function keyExpansion(keyBytes) {
  if (keyBytes.length !== 16) throw new Error("Key must be 16 bytes for AES-128");
  const w = new Uint8Array(44 * 4); // 44 words of 4 bytes
  // Initial 4 words are the cipher key
  for (let i = 0; i < 16; i++) {
    w[i] = keyBytes[i];
  }

  const temp = new Uint8Array(4);
  for (let i = 4; i < 44; i++) {
    const prev = (i - 1) * 4;
    temp[0] = w[prev];
    temp[1] = w[prev + 1];
    temp[2] = w[prev + 2];
    temp[3] = w[prev + 3];

    if (i % 4 === 0) {
      // RotWord: cyclic shift left
      const t0 = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = t0;

      // SubWord
      temp[0] = SBOX[temp[0]];
      temp[1] = SBOX[temp[1]];
      temp[2] = SBOX[temp[2]];
      temp[3] = SBOX[temp[3]];

      // XOR with Rcon[i/4]
      temp[0] ^= RCON[i / 4];
    }

    const cur = i * 4;
    const old = (i - 4) * 4;
    w[cur] = w[old] ^ temp[0];
    w[cur + 1] = w[old + 1] ^ temp[1];
    w[cur + 2] = w[old + 2] ^ temp[2];
    w[cur + 3] = w[old + 3] ^ temp[3];
  }

  // Slice into 11 round keys of 16 bytes each
  const roundKeys = [];
  for (let r = 0; r <= 10; r++) {
    roundKeys.push(w.slice(r * 16, (r + 1) * 16));
  }
  return roundKeys;
}

// Matrix helper: 16 bytes Uint8Array to 4x4 2D array [row][col] (Column-major standard)
// State byte at index i: row = i % 4, col = Math.floor(i / 4)
function bytesToMatrix(bytes) {
  const m = [
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0]
  ];
  for (let c = 0; c < 4; c++) {
    for (let r = 0; r < 4; r++) {
      m[r][c] = bytes[c * 4 + r];
    }
  }
  return m;
}

function matrixToBytes(m) {
  const bytes = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    for (let r = 0; r < 4; r++) {
      bytes[c * 4 + r] = m[r][c];
    }
  }
  return bytes;
}

function cloneMatrix(m) {
  return m.map(row => [...row]);
}

// AES Transformations on 4x4 matrix
function applySubBytes(state) {
  const out = cloneMatrix(state);
  for (let r = 0; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      out[r][c] = SBOX[out[r][c]];
    }
  }
  return out;
}

function applyShiftRows(state) {
  const out = cloneMatrix(state);
  // Row 0: no shift
  // Row 1: left shift 1
  const r1_0 = out[1][0];
  out[1][0] = out[1][1];
  out[1][1] = out[1][2];
  out[1][2] = out[1][3];
  out[1][3] = r1_0;

  // Row 2: left shift 2
  const r2_0 = out[2][0], r2_1 = out[2][1];
  out[2][0] = out[2][2];
  out[2][1] = out[2][3];
  out[2][2] = r2_0;
  out[2][3] = r2_1;

  // Row 3: left shift 3
  const r3_3 = out[3][3];
  out[3][3] = out[3][2];
  out[3][2] = out[3][1];
  out[3][1] = out[3][0];
  out[3][0] = r3_3;

  return out;
}

function applyMixColumns(state) {
  const out = cloneMatrix(state);
  for (let c = 0; c < 4; c++) {
    const s0 = state[0][c];
    const s1 = state[1][c];
    const s2 = state[2][c];
    const s3 = state[3][c];

    // MixColumns standard polynomial matrix multiplication in GF(2^8):
    // [02 03 01 01]
    // [01 02 03 01]
    // [01 01 02 03]
    // [03 01 01 02]
    out[0][c] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
    out[1][c] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
    out[2][c] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
    out[3][c] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
  }
  return out;
}

function applyAddRoundKey(state, roundKeyBytes) {
  const keyMat = bytesToMatrix(roundKeyBytes);
  const out = cloneMatrix(state);
  for (let r = 0; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      out[r][c] ^= keyMat[r][c];
    }
  }
  return out;
}

// Full AES-128 execution trace generator
function traceAES128(plaintextBytes, keyBytes) {
  if (plaintextBytes.length !== 16) throw new Error("Plaintext must be 16 bytes");
  if (keyBytes.length !== 16) throw new Error("Key must be 16 bytes");

  const roundKeys = keyExpansion(keyBytes);
  const steps = [];

  // Initial State
  let curState = bytesToMatrix(plaintextBytes);

  // Round 0: Pre-Round AddRoundKey
  const r0Key = roundKeys[0];
  const postPreKey = applyAddRoundKey(curState, r0Key);
  steps.push({
    round: 0,
    op: "AddRoundKey",
    name: "Initial AddRoundKey",
    shortName: "AddRoundKey",
    inputState: cloneMatrix(curState),
    outputState: cloneMatrix(postPreKey),
    roundKey: r0Key,
    explanation: "Bitwise XOR between the initial 128-bit input plaintext block and the primary Cipher Key (Round Key 0)."
  });
  curState = postPreKey;

  // Rounds 1 to 9 (4 steps per round)
  for (let r = 1; r <= 9; r++) {
    // 1. SubBytes
    const postSub = applySubBytes(curState);
    steps.push({
      round: r,
      op: "SubBytes",
      name: `Round ${r}: SubBytes`,
      shortName: "SubBytes",
      inputState: cloneMatrix(curState),
      outputState: cloneMatrix(postSub),
      explanation: "Non-linear byte substitution using the Rijndael S-Box table, providing cryptographic confusion."
    });
    curState = postSub;

    // 2. ShiftRows
    const postShift = applyShiftRows(curState);
    steps.push({
      round: r,
      op: "ShiftRows",
      name: `Round ${r}: ShiftRows`,
      shortName: "ShiftRows",
      inputState: cloneMatrix(curState),
      outputState: cloneMatrix(postShift),
      explanation: "Cyclic left-shift of state rows (Row 0: 0, Row 1: 1, Row 2: 2, Row 3: 3 bytes) creating spatial diffusion."
    });
    curState = postShift;

    // 3. MixColumns
    const postMix = applyMixColumns(curState);
    steps.push({
      round: r,
      op: "MixColumns",
      name: `Round ${r}: MixColumns`,
      shortName: "MixColumns",
      inputState: cloneMatrix(curState),
      outputState: cloneMatrix(postMix),
      explanation: "Linear matrix multiplication over Galois Field GF(2^8) mixing column bytes for high branch number diffusion."
    });
    curState = postMix;

    // 4. AddRoundKey
    const rk = roundKeys[r];
    const postKey = applyAddRoundKey(curState, rk);
    steps.push({
      round: r,
      op: "AddRoundKey",
      name: `Round ${r}: AddRoundKey`,
      shortName: "AddRoundKey",
      inputState: cloneMatrix(curState),
      outputState: cloneMatrix(postKey),
      roundKey: rk,
      explanation: `Bitwise XOR with expanded Round Key ${r} derived from the Rijndael key schedule.`
    });
    curState = postKey;
  }

  // Round 10: Final Round (MixColumns omitted)
  // 1. SubBytes
  const postSub10 = applySubBytes(curState);
  steps.push({
    round: 10,
    op: "SubBytes",
    name: "Round 10: SubBytes",
    shortName: "SubBytes",
    inputState: cloneMatrix(curState),
    outputState: cloneMatrix(postSub10),
    explanation: "Non-linear byte substitution via the S-Box table in the final round."
  });
  curState = postSub10;

  // 2. ShiftRows
  const postShift10 = applyShiftRows(curState);
  steps.push({
    round: 10,
    op: "ShiftRows",
    name: "Round 10: ShiftRows",
    shortName: "ShiftRows",
    inputState: cloneMatrix(curState),
    outputState: cloneMatrix(postShift10),
    explanation: "Cyclic left-shift of rows in the final round."
  });
  curState = postShift10;

  // 3. AddRoundKey (MixColumns is deliberately omitted in Round 10)
  const r10Key = roundKeys[10];
  const postKey10 = applyAddRoundKey(curState, r10Key);
  steps.push({
    round: 10,
    op: "AddRoundKey",
    name: "Round 10: AddRoundKey (Final)",
    shortName: "AddRoundKey",
    inputState: cloneMatrix(curState),
    outputState: cloneMatrix(postKey10),
    roundKey: r10Key,
    explanation: "Final Round bitwise XOR with Round Key 10. MixColumns is omitted to ensure encryption/decryption architectural symmetry."
  });
  curState = postKey10;

  const finalCiphertext = matrixToBytes(curState);
  return {
    steps,
    roundKeys,
    finalCiphertext
  };
}

module.exports = {
  SBOX,
  RCON,
  xtime,
  keyExpansion,
  bytesToMatrix,
  matrixToBytes,
  applySubBytes,
  applyShiftRows,
  applyMixColumns,
  applyAddRoundKey,
  traceAES128
};
