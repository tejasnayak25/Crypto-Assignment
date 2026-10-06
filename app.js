/**
 * CFB Mode Virtual Lab - Assignment Project
 * Clean, standard implementation of AES-128 and CFB mode.
 */

// --- Rijndael S-Box and Rcon ---
const S_BOX = [
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
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

function xtime(a) {
  return (a & 0x80) ? (((a << 1) ^ 0x1B) & 0xFF) : ((a << 1) & 0xFF);
}

// Standard AES-128 implementation
class AES128 {
  constructor(keyBytes) {
    this.roundKeys = this._keyExpansion(keyBytes);
  }

  _keyExpansion(key) {
    const w = [];
    for (let i = 0; i < 4; i++) {
      w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for (let i = 4; i < 44; i++) {
      let temp = [...w[i - 1]];
      if (i % 4 === 0) {
        temp = [temp[1], temp[2], temp[3], temp[0]];
        temp = temp.map(b => S_BOX[b]);
        temp[0] ^= RCON[Math.floor(i / 4)];
      }
      w.push([
        w[i - 4][0] ^ temp[0],
        w[i - 4][1] ^ temp[1],
        w[i - 4][2] ^ temp[2],
        w[i - 4][3] ^ temp[3],
      ]);
    }

    const roundKeys = [];
    for (let r = 0; r <= 10; r++) {
      const state = Array.from({ length: 4 }, () => [0, 0, 0, 0]);
      for (let col = 0; col < 4; col++) {
        for (let row = 0; row < 4; row++) {
          state[row][col] = w[r * 4 + col][row];
        }
      }
      roundKeys.push(state);
    }
    return roundKeys;
  }

  encryptBlock(block) {
    const state = Array.from({ length: 4 }, () => [0, 0, 0, 0]);
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) {
        state[r][c] = block[r + 4 * c];
      }
    }

    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) state[r][c] ^= this.roundKeys[0][r][c];
    }

    for (let rnd = 1; rnd < 10; rnd++) {
      for (let r = 0; r < 4; r++) {
        for (let c = 0; c < 4; c++) state[r][c] = S_BOX[state[r][c]];
      }
      state[1] = [state[1][1], state[1][2], state[1][3], state[1][0]];
      state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]];
      state[3] = [state[3][3], state[3][0], state[3][1], state[3][2]];
      for (let c = 0; c < 4; c++) {
        const s0 = state[0][c], s1 = state[1][c], s2 = state[2][c], s3 = state[3][c];
        state[0][c] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
        state[1][c] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
        state[2][c] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
        state[3][c] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
      }
      for (let r = 0; r < 4; r++) {
        for (let c = 0; c < 4; c++) state[r][c] ^= this.roundKeys[rnd][r][c];
      }
    }

    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) state[r][c] = S_BOX[state[r][c]];
    }
    state[1] = [state[1][1], state[1][2], state[1][3], state[1][0]];
    state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]];
    state[3] = [state[3][3], state[3][0], state[3][1], state[3][2]];
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) state[r][c] ^= this.roundKeys[10][r][c];
    }

    const out = new Uint8Array(16);
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) out[r + 4 * c] = state[r][c];
    }
    return out;
  }
}

// --- CFB Mode Engine ---
const BLOCK_SIZE = 16;

function cfbProcess(keyBytes, ivBytes, dataBytes, isEncrypt = true) {
  const aes = new AES128(keyBytes);
  let register = new Uint8Array(ivBytes);
  const output = new Uint8Array(dataBytes.length);
  const steps = [];

  let blockIdx = 1;
  for (let offset = 0; offset < dataBytes.length; offset += BLOCK_SIZE) {
    const chunkLen = Math.min(BLOCK_SIZE, dataBytes.length - offset);
    const chunk = dataBytes.subarray(offset, offset + chunkLen);

    // Keystream derived by encrypting current register
    const cipherOutput = aes.encryptBlock(register);
    const keystream = cipherOutput.subarray(0, chunkLen);

    // XOR
    const transformed = new Uint8Array(chunkLen);
    for (let i = 0; i < chunkLen; i++) {
      transformed[i] = chunk[i] ^ keystream[i];
    }
    output.set(transformed, offset);

    // In CFB, ciphertext is always fed back to shift register
    const cipherSegment = isEncrypt ? transformed : chunk;
    const plainSegment = isEncrypt ? chunk : transformed;

    const nextRegister = new Uint8Array(16);
    nextRegister.set(register.subarray(chunkLen), 0);
    nextRegister.set(cipherSegment, 16 - chunkLen);

    steps.push({
      blockNum: blockIdx,
      inputRegister: new Uint8Array(register),
      keystream: new Uint8Array(keystream),
      plainData: new Uint8Array(plainSegment),
      cipherData: new Uint8Array(cipherSegment),
      nextRegister: new Uint8Array(nextRegister),
      isEncrypt: isEncrypt
    });

    register = nextRegister;
    blockIdx++;
  }

  return { output, steps };
}

// --- Helpers ---
function hexToBytes(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function strToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToStr(bytes) {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

function randomHex(len = 16) {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return bytesToHex(b);
}

// --- Application Logic ---
class CFBLab {
  constructor() {
    this.currentMode = 'encrypt';
    this.currentStepIdx = 0;
    this.steps = [];
    this.lastCiphertext = null;

    this.cacheElements();
    this.attachEvents();
    this.runEncryption();
  }

  cacheElements() {
    this.plainTextInput = document.getElementById('plainTextInput');
    this.keyInput = document.getElementById('keyInput');
    this.ivInput = document.getElementById('ivInput');
    this.msgLengthHint = document.getElementById('msgLengthHint');

    this.encryptBtn = document.getElementById('encryptBtn');
    this.decryptBtn = document.getElementById('decryptBtn');
    this.resetBtn = document.getElementById('resetBtn');
    this.randomKeyBtn = document.getElementById('randomKeyBtn');
    this.randomIvBtn = document.getElementById('randomIvBtn');

    this.processTitle = document.getElementById('processTitle');
    this.prevStepBtn = document.getElementById('prevStepBtn');
    this.nextStepBtn = document.getElementById('nextStepBtn');
    this.stepCounter = document.getElementById('stepCounter');

    this.diagRegisterText = document.getElementById('diagRegisterText');
    this.diagKeystreamText = document.getElementById('diagKeystreamText');
    this.diagInputLabel = document.getElementById('diagInputLabel');
    this.diagInputText = document.getElementById('diagInputText');
    this.diagOutputLabel = document.getElementById('diagOutputLabel');
    this.diagOutputText = document.getElementById('diagOutputText');

    this.stepBreakdownTitle = document.getElementById('stepBreakdownTitle');
    this.stepMathText = document.getElementById('stepMathText');

    this.resOriginalText = document.getElementById('resOriginalText');
    this.resCiphertextHex = document.getElementById('resCiphertextHex');
    this.resDecryptedText = document.getElementById('resDecryptedText');
    this.verifyStatus = document.getElementById('verifyStatus');

    this.traceTableBody = document.getElementById('traceTableBody');
  }

  attachEvents() {
    this.plainTextInput.addEventListener('input', () => {
      const len = this.plainTextInput.value.length;
      const blocks = Math.ceil(len / 16) || 1;
      this.msgLengthHint.textContent = `Length: ${len} bytes (${blocks} block${blocks > 1 ? 's' : ''})`;
      this.runEncryption();
    });

    this.keyInput.addEventListener('input', () => this.runEncryption());
    this.ivInput.addEventListener('input', () => this.runEncryption());

    this.randomKeyBtn.addEventListener('click', () => {
      this.keyInput.value = randomHex(16);
      this.runEncryption();
    });

    this.randomIvBtn.addEventListener('click', () => {
      this.ivInput.value = randomHex(16);
      this.runEncryption();
    });

    this.resetBtn.addEventListener('click', () => {
      this.plainTextInput.value = "Cryptography Lab Assignment - CFB Mode";
      this.keyInput.value = "2b7e151628aed2a6abf7158809cf4f3c";
      this.ivInput.value = "000102030405060708090a0b0c0d0e0f";
      const len = this.plainTextInput.value.length;
      this.msgLengthHint.textContent = `Length: ${len} bytes (3 blocks)`;
      this.runEncryption();
    });

    this.encryptBtn.addEventListener('click', () => this.runEncryption());
    this.decryptBtn.addEventListener('click', () => this.runDecryption());

    this.prevStepBtn.addEventListener('click', () => this.showStep(this.currentStepIdx - 1));
    this.nextStepBtn.addEventListener('click', () => this.showStep(this.currentStepIdx + 1));
  }

  runEncryption() {
    this.currentMode = 'encrypt';
    this.processTitle.textContent = "Process Visualization: Encryption";
    this.execute(true);
  }

  runDecryption() {
    this.currentMode = 'decrypt';
    this.processTitle.textContent = "Process Visualization: Decryption";
    this.execute(false);
  }

  execute(isEncrypt = true) {
    try {
      const keyBytes = hexToBytes(this.keyInput.value);
      const ivBytes = hexToBytes(this.ivInput.value);
      const textMsg = this.plainTextInput.value;
      const textBytes = strToBytes(textMsg);

      if (keyBytes.length !== 16 || ivBytes.length !== 16) {
        return;
      }

      // 1. Encryption
      const encResult = cfbProcess(keyBytes, ivBytes, textBytes, true);
      this.lastCiphertext = encResult.output;
      const cipherHex = bytesToHex(encResult.output);

      // 2. Decryption
      const decResult = cfbProcess(keyBytes, ivBytes, this.lastCiphertext, false);
      const decryptedString = bytesToStr(decResult.output);

      this.steps = isEncrypt ? encResult.steps : decResult.steps;

      // Update Results
      this.resOriginalText.textContent = textMsg;
      this.resCiphertextHex.textContent = cipherHex;
      this.resDecryptedText.textContent = decryptedString;

      const isMatch = (textMsg === decryptedString);
      if (isMatch) {
        this.verifyStatus.textContent = "Decryption matched original plaintext.";
        this.verifyStatus.style.color = "#166534";
        this.verifyStatus.style.backgroundColor = "#f0fdf4";
        this.verifyStatus.style.borderColor = "#bbf7d0";
      } else {
        this.verifyStatus.textContent = "Decryption mismatch.";
        this.verifyStatus.style.color = "#991b1b";
        this.verifyStatus.style.backgroundColor = "#fef2f2";
        this.verifyStatus.style.borderColor = "#fecaca";
      }

      // Populate Table
      this.renderTable(encResult.steps);
      this.showStep(0);

    } catch (e) {
      console.error(e);
    }
  }

  showStep(idx) {
    if (this.steps.length === 0) return;
    if (idx < 0) idx = 0;
    if (idx >= this.steps.length) idx = this.steps.length - 1;

    this.currentStepIdx = idx;
    const step = this.steps[idx];
    const total = this.steps.length;

    this.stepCounter.textContent = `Block ${step.blockNum} of ${total}`;
    this.prevStepBtn.disabled = (idx === 0);
    this.nextStepBtn.disabled = (idx === total - 1);

    const regHex = bytesToHex(step.inputRegister);
    const ksHex = bytesToHex(step.keystream);
    const pText = bytesToStr(step.plainData);
    const cHex = bytesToHex(step.cipherData);

    this.diagRegisterText.textContent = regHex;
    this.diagKeystreamText.textContent = ksHex.substring(0, 16) + "...";

    if (this.currentMode === 'encrypt') {
      this.diagInputLabel.textContent = `Plaintext (P_${step.blockNum})`;
      this.diagInputText.textContent = `"${pText.substring(0, 12)}..."`;
      this.diagOutputLabel.textContent = `Ciphertext (C_${step.blockNum})`;
      this.diagOutputText.textContent = cHex.substring(0, 16) + "...";
    } else {
      this.diagInputLabel.textContent = `Ciphertext (C_${step.blockNum})`;
      this.diagInputText.textContent = cHex.substring(0, 12) + "...";
      this.diagOutputLabel.textContent = `Plaintext (P_${step.blockNum})`;
      this.diagOutputText.textContent = `"${pText.substring(0, 12)}..."`;
    }

    this.stepBreakdownTitle.textContent = `Block ${step.blockNum} Calculations (${this.currentMode === 'encrypt' ? 'Encryption' : 'Decryption'}):`;

    if (this.currentMode === 'encrypt') {
      this.stepMathText.innerHTML = [
        `Register (I_${step.blockNum}) = ${step.blockNum === 1 ? 'IV' : `C_${step.blockNum - 1}`} = ${regHex}`,
        `Keystream (S_${step.blockNum}) = AES(Key, I_${step.blockNum}) = ${ksHex}`,
        `Plaintext (P_${step.blockNum}) = "${pText}" (hex: ${bytesToHex(step.plainData)})`,
        `Ciphertext (C_${step.blockNum}) = P_${step.blockNum} XOR S_${step.blockNum} = ${cHex}`,
        `Feedback: C_${step.blockNum} is fed into the register for Block ${step.blockNum + 1}`
      ].join('<br>');
    } else {
      this.stepMathText.innerHTML = [
        `Register (I_${step.blockNum}) = ${step.blockNum === 1 ? 'IV' : `C_${step.blockNum - 1}`} = ${regHex}`,
        `Keystream (S_${step.blockNum}) = AES(Key, I_${step.blockNum}) = ${ksHex}`,
        `Ciphertext (C_${step.blockNum}) = ${cHex}`,
        `Plaintext (P_${step.blockNum}) = C_${step.blockNum} XOR S_${step.blockNum} = "${pText}" (hex: ${bytesToHex(step.plainData)})`,
        `Feedback: C_${step.blockNum} is fed into the register for Block ${step.blockNum + 1}`
      ].join('<br>');
    }

    const rows = this.traceTableBody.querySelectorAll('tr');
    rows.forEach((r, i) => {
      r.classList.toggle('active-row', i === idx);
    });
  }

  renderTable(steps) {
    this.traceTableBody.innerHTML = '';
    steps.forEach((s, idx) => {
      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      tr.addEventListener('click', () => this.showStep(idx));

      tr.innerHTML = `
        <td><strong>Block ${s.blockNum}</strong></td>
        <td>${bytesToHex(s.inputRegister)}</td>
        <td>${bytesToHex(s.keystream)}</td>
        <td>"${bytesToStr(s.plainData)}"</td>
        <td>${bytesToHex(s.cipherData)}</td>
        <td>${bytesToHex(s.nextRegister)}</td>
      `;
      this.traceTableBody.appendChild(tr);
    });
  }
}

window.addEventListener('DOMContentLoaded', () => {
  new CFBLab();
});
