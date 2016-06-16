kryptos.hash.SHA512 = function(str) {
  inherit(this, new kryptos.hash.baseHash(str));
}

kryptos.hash.SHA512.digest_size = 64;

kryptos.hash.SHA512.prototype = {
  type : 'sha512'
};


// http://code.google.com/p/crypto-js/source/browse/branches/4.x/src/sha512.js
// BSD license: http://www.opensource.org/licenses/bsd-license.php
if (!(Components && Components.classes)) {  // Chrome
  kryptos.hash.SHA512.prototype = {
    digest: function() {
      var hashData = kryptos.toByteArray(this.data);

      var _state = [
          0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b,
          0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
          0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
          0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179
      ];

      // Constants table
      var ROUND_CONSTANTS = [
          0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
          0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
          0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
          0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
          0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
          0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
          0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
          0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
          0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
          0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
          0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
          0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
          0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
          0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
          0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
          0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
          0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
          0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
          0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
          0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
      ];

      // Reusable object for expanded message
      var M = [];

      var m = kryptos.bytesToWords(hashData),
          l = hashData.length * 8;

      // Padding
      m[l >> 5] |= 0x80 << (24 - l % 32);
      m[((l + 128 >> 10) << 5) + 30] = Math.floor(l / 0x100000000);
      m[((l + 128 >> 10) << 5) + 31] = l;

      for (var i = 0; i < m.length; i += 32) {
        // Shortcuts
        var s = _state;
        var s0Msw = s[0];
        var s0Lsw = s[1];
        var s1Msw = s[2];
        var s1Lsw = s[3];
        var s2Msw = s[4];
        var s2Lsw = s[5];
        var s3Msw = s[6];
        var s3Lsw = s[7];
        var s4Msw = s[8];
        var s4Lsw = s[9];
        var s5Msw = s[10];
        var s5Lsw = s[11];
        var s6Msw = s[12];
        var s6Lsw = s[13];
        var s7Msw = s[14];
        var s7Lsw = s[15];
        var _s0Msw = s0Msw;
        var _s0Lsw = s0Lsw;
        var _s1Msw = s1Msw;
        var _s1Lsw = s1Lsw;
        var _s2Msw = s2Msw;
        var _s2Lsw = s2Lsw;
        var _s3Msw = s3Msw;
        var _s3Lsw = s3Lsw;
        var _s4Msw = s4Msw;
        var _s4Lsw = s4Lsw;
        var _s5Msw = s5Msw;
        var _s5Lsw = s5Lsw;
        var _s6Msw = s6Msw;
        var _s6Lsw = s6Lsw;
        var _s7Msw = s7Msw;
        var _s7Lsw = s7Lsw;

        // Expand message
        for (var round = 0; round < 160; round += 2) {
            if (round < 32) {
                var MRoundMsw = m[i + round];
                var MRoundLsw = m[i + round + 1];
            } else {
                // Shortcuts
                var MRound2Msw  = M[round - 4];
                var MRound2Lsw  = M[round - 3];
                var MRound7Msw  = M[round - 14];
                var MRound7Lsw  = M[round - 13];
                var MRound15Msw = M[round - 30];
                var MRound15Lsw = M[round - 29];
                var MRound16Msw = M[round - 32];
                var MRound16Lsw = M[round - 31];

                // gamma0
                var gamma0Msw = (
                    ((MRound15Lsw << 31) | (MRound15Msw >>> 1)) ^
                    ((MRound15Lsw << 24) | (MRound15Msw >>> 8)) ^
                    (MRound15Msw >>> 7)
                );
                var gamma0Lsw = (
                    ((MRound15Msw << 31) | (MRound15Lsw >>> 1)) ^
                    ((MRound15Msw << 24) | (MRound15Lsw >>> 8)) ^
                    ((MRound15Msw << 25) | (MRound15Lsw >>> 7))
                );

                // gamma1
                var gamma1Msw = (
                    ((MRound2Lsw << 13) | (MRound2Msw >>> 19)) ^
                    ((MRound2Msw << 3)  | (MRound2Lsw >>> 29)) ^
                    (MRound2Msw >>> 6)
                );
                var gamma1Lsw = (
                    ((MRound2Msw << 13) | (MRound2Lsw >>> 19)) ^
                    ((MRound2Lsw << 3)  | (MRound2Msw >>> 29)) ^
                    ((MRound2Msw << 26) | (MRound2Lsw >>> 6))
                );

                // gamma0 + gamma1
                var t0Lsw = gamma0Lsw + gamma1Lsw;
                var t0Msw = gamma0Msw + gamma1Msw + ((t0Lsw >>> 0) < (gamma0Lsw >>> 0) ? 1 : 0);

                // M[round - 7] + M[round - 16]
                var t1Lsw = MRound7Lsw + MRound16Lsw;
                var t1Msw = MRound7Msw + MRound16Msw + ((t1Lsw >>> 0) < (MRound7Lsw >>> 0) ? 1 : 0);

                // (gamma0 + gamma1) + (M[round - 7] + M[round - 16])
                var MRoundLsw = t0Lsw + t1Lsw;
                var MRoundMsw = t0Msw + t1Msw + ((MRoundLsw >>> 0) < (t0Lsw >>> 0) ? 1 : 0);
            }

            // Set expanded message
            M[round]     = MRoundMsw |= 0;
            M[round + 1] = MRoundLsw |= 0;
        }

        // Rounds
        for (var round = 0; round < 160; round += 16) {
            // Inline round 1
            {
                // Shortcuts
                var MRoundMsw = M[round];
                var MRoundLsw = M[round + 1];
                var roundConstantMsw = ROUND_CONSTANTS[round];
                var roundConstantLsw = ROUND_CONSTANTS[round + 1];

                // ch
                var chMsw = (s4Msw & s5Msw) ^ (~s4Msw & s6Msw);
                var chLsw = (s4Lsw & s5Lsw) ^ (~s4Lsw & s6Lsw);

                // maj
                var majMsw = (s0Msw & s1Msw) ^ (s0Msw & s2Msw) ^ (s1Msw & s2Msw);
                var majLsw = (s0Lsw & s1Lsw) ^ (s0Lsw & s2Lsw) ^ (s1Lsw & s2Lsw);

                // sigma0
                var sigma0Msw = (
                    ((s0Lsw << 4)  | (s0Msw >>> 28)) ^
                    ((s0Msw << 30) | (s0Lsw >>> 2))  ^
                    ((s0Msw << 25) | (s0Lsw >>> 7))
                );
                var sigma0Lsw = (
                    ((s0Msw << 4)  | (s0Lsw >>> 28)) ^
                    ((s0Lsw << 30) | (s0Msw >>> 2))  ^
                    ((s0Lsw << 25) | (s0Msw >>> 7))
                );

                // sigma1
                var sigma1Msw = (
                    ((s4Lsw << 18) | (s4Msw >>> 14)) ^
                    ((s4Lsw << 14) | (s4Msw >>> 18)) ^
                    ((s4Msw << 23) | (s4Lsw >>> 9))
                );
                var sigma1Lsw = (
                    ((s4Msw << 18) | (s4Lsw >>> 14)) ^
                    ((s4Msw << 14) | (s4Lsw >>> 18)) ^
                    ((s4Lsw << 23) | (s4Msw >>> 9))
                );

                // ch + sigma1
                var t0Lsw = chLsw + sigma1Lsw;
                var t0Msw = chMsw + sigma1Msw + ((t0Lsw >>> 0) < (chLsw >>> 0) ? 1 : 0);

                // M[round] + ROUND_CONSTANTS[round]
                var t1Lsw = MRoundLsw + roundConstantLsw;
                var t1Msw = MRoundMsw + roundConstantMsw + ((t1Lsw >>> 0) < (MRoundLsw >>> 0) ? 1 : 0);

                // (ch + sigma1) + (M[round] + ROUND_CONSTANTS[round])
                var t2Lsw = t0Lsw + t1Lsw;
                var t2Msw = t0Msw + t1Msw + ((t2Lsw >>> 0) < (t0Lsw >>> 0) ? 1 : 0);

                // s7 + ((ch + sigma1) + (M[round] + ROUND_CONSTANTS[round]))
                var t3Lsw = s7Lsw + t2Lsw;
                var t3Msw = s7Msw + t2Msw + ((t3Lsw >>> 0) < (t2Lsw >>> 0) ? 1 : 0);

                // maj + sigma0
                var t4Lsw = majLsw + sigma0Lsw;
                var t4Msw = majMsw + sigma0Msw + ((t4Lsw >>> 0) < (majLsw >>> 0) ? 1 : 0);

                // Update working state
                s3Lsw = (s3Lsw + t3Lsw) | 0;
                s3Msw = (s3Msw + t3Msw + ((s3Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
                s7Lsw = (t3Lsw + t4Lsw) | 0;
                s7Msw = (t3Msw + t4Msw + ((s7Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
            }

            // Inline round 2
            {
                // Shortcuts
                var MRoundMsw = M[round + 2];
                var MRoundLsw = M[round + 3];
                var roundConstantMsw = ROUND_CONSTANTS[round + 2];
                var roundConstantLsw = ROUND_CONSTANTS[round + 3];

                // ch
                var chMsw = (s3Msw & s4Msw) ^ (~s3Msw & s5Msw);
                var chLsw = (s3Lsw & s4Lsw) ^ (~s3Lsw & s5Lsw);

                // maj
                var majMsw = (s7Msw & s0Msw) ^ (s7Msw & s1Msw) ^ (s0Msw & s1Msw);
                var majLsw = (s7Lsw & s0Lsw) ^ (s7Lsw & s1Lsw) ^ (s0Lsw & s1Lsw);

                // sigma0
                var sigma0Msw = (
                    ((s7Lsw << 4)  | (s7Msw >>> 28)) ^
                    ((s7Msw << 30) | (s7Lsw >>> 2))  ^
                    ((s7Msw << 25) | (s7Lsw >>> 7))
                );
                var sigma0Lsw = (
                    ((s7Msw << 4)  | (s7Lsw >>> 28)) ^
                    ((s7Lsw << 30) | (s7Msw >>> 2))  ^
                    ((s7Lsw << 25) | (s7Msw >>> 7))
                );

                // sigma1
                var sigma1Msw = (
                    ((s3Lsw << 18) | (s3Msw >>> 14)) ^
                    ((s3Lsw << 14) | (s3Msw >>> 18)) ^
                    ((s3Msw << 23) | (s3Lsw >>> 9))
                );
                var sigma1Lsw = (
                    ((s3Msw << 18) | (s3Lsw >>> 14)) ^
                    ((s3Msw << 14) | (s3Lsw >>> 18)) ^
                    ((s3Lsw << 23) | (s3Msw >>> 9))
                );

                // ch + sigma1
                var t0Lsw = chLsw + sigma1Lsw;
                var t0Msw = chMsw + sigma1Msw + ((t0Lsw >>> 0) < (chLsw >>> 0) ? 1 : 0);

                // M[round] + ROUND_CONSTANTS[round]
                var t1Lsw = MRoundLsw + roundConstantLsw;
                var t1Msw = MRoundMsw + roundConstantMsw + ((t1Lsw >>> 0) < (MRoundLsw >>> 0) ? 1 : 0);

                // (ch + sigma1) + (M[round] + ROUND_CONSTANTS[round])
                var t2Lsw = t0Lsw + t1Lsw;
                var t2Msw = t0Msw + t1Msw + ((t2Lsw >>> 0) < (t0Lsw >>> 0) ? 1 : 0);

                // s6 + ((ch + sigma1) + (M[round] + ROUND_CONSTANTS[round]))
                var t3Lsw = s6Lsw + t2Lsw;
                var t3Msw = s6Msw + t2Msw + ((t3Lsw >>> 0) < (t2Lsw >>> 0) ? 1 : 0);

                // maj + sigma0
                var t4Lsw = majLsw + sigma0Lsw;
                var t4Msw = majMsw + sigma0Msw + ((t4Lsw >>> 0) < (majLsw >>> 0) ? 1 : 0);

                // Update working state
                s2Lsw = (s2Lsw + t3Lsw) | 0;
                s2Msw = (s2Msw + t3Msw + ((s2Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
                s6Lsw = (t3Lsw + t4Lsw) | 0;
                s6Msw = (t3Msw + t4Msw + ((s6Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
            }

            // Inline round 3
            {
                // Shortcuts
                var MRoundMsw = M[round + 4];
                var MRoundLsw = M[round + 5];
                var roundConstantMsw = ROUND_CONSTANTS[round + 4];
                var roundConstantLsw = ROUND_CONSTANTS[round + 5];

                // ch
                var chMsw = (s2Msw & s3Msw) ^ (~s2Msw & s4Msw);
                var chLsw = (s2Lsw & s3Lsw) ^ (~s2Lsw & s4Lsw);

                // maj
                var majMsw = (s6Msw & s7Msw) ^ (s6Msw & s0Msw) ^ (s7Msw & s0Msw);
                var majLsw = (s6Lsw & s7Lsw) ^ (s6Lsw & s0Lsw) ^ (s7Lsw & s0Lsw);

                // sigma0
                var sigma0Msw = (
                    ((s6Lsw << 4)  | (s6Msw >>> 28)) ^
                    ((s6Msw << 30) | (s6Lsw >>> 2))  ^
                    ((s6Msw << 25) | (s6Lsw >>> 7))
                );
                var sigma0Lsw = (
                    ((s6Msw << 4)  | (s6Lsw >>> 28)) ^
                    ((s6Lsw << 30) | (s6Msw >>> 2))  ^
                    ((s6Lsw << 25) | (s6Msw >>> 7))
                );

                // sigma1
                var sigma1Msw = (
                    ((s2Lsw << 18) | (s2Msw >>> 14)) ^
                    ((s2Lsw << 14) | (s2Msw >>> 18)) ^
                    ((s2Msw << 23) | (s2Lsw >>> 9))
                );
                var sigma1Lsw = (
                    ((s2Msw << 18) | (s2Lsw >>> 14)) ^
                    ((s2Msw << 14) | (s2Lsw >>> 18)) ^
                    ((s2Lsw << 23) | (s2Msw >>> 9))
                );

                // ch + sigma1
                var t0Lsw = chLsw + sigma1Lsw;
                var t0Msw = chMsw + sigma1Msw + ((t0Lsw >>> 0) < (chLsw >>> 0) ? 1 : 0);

                // M[round] + ROUND_CONSTANTS[round]
                var t1Lsw = MRoundLsw + roundConstantLsw;
                var t1Msw = MRoundMsw + roundConstantMsw + ((t1Lsw >>> 0) < (MRoundLsw >>> 0) ? 1 : 0);

                // (ch + sigma1) + (M[round] + ROUND_CONSTANTS[round])
                var t2Lsw = t0Lsw + t1Lsw;
                var t2Msw = t0Msw + t1Msw + ((t2Lsw >>> 0) < (t0Lsw >>> 0) ? 1 : 0);

                // s5 + ((ch + sigma1) + (M[round] + ROUND_CONSTANTS[round]))
                var t3Lsw = s5Lsw + t2Lsw;
                var t3Msw = s5Msw + t2Msw + ((t3Lsw >>> 0) < (t2Lsw >>> 0) ? 1 : 0);

                // maj + sigma0
                var t4Lsw = majLsw + sigma0Lsw;
                var t4Msw = majMsw + sigma0Msw + ((t4Lsw >>> 0) < (majLsw >>> 0) ? 1 : 0);

                // Update working state
                s1Lsw = (s1Lsw + t3Lsw) | 0;
                s1Msw = (s1Msw + t3Msw + ((s1Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
                s5Lsw = (t3Lsw + t4Lsw) | 0;
                s5Msw = (t3Msw + t4Msw + ((s5Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
            }

            // Inline round 4
            {
                // Shortcuts
                var MRoundMsw = M[round + 6];
                var MRoundLsw = M[round + 7];
                var roundConstantMsw = ROUND_CONSTANTS[round + 6];
                var roundConstantLsw = ROUND_CONSTANTS[round + 7];

                // ch
                var chMsw = (s1Msw & s2Msw) ^ (~s1Msw & s3Msw);
                var chLsw = (s1Lsw & s2Lsw) ^ (~s1Lsw & s3Lsw);

                // maj
                var majMsw = (s5Msw & s6Msw) ^ (s5Msw & s7Msw) ^ (s6Msw & s7Msw);
                var majLsw = (s5Lsw & s6Lsw) ^ (s5Lsw & s7Lsw) ^ (s6Lsw & s7Lsw);

                // sigma0
                var sigma0Msw = (
                    ((s5Lsw << 4)  | (s5Msw >>> 28)) ^
                    ((s5Msw << 30) | (s5Lsw >>> 2))  ^
                    ((s5Msw << 25) | (s5Lsw >>> 7))
                );
                var sigma0Lsw = (
                    ((s5Msw << 4)  | (s5Lsw >>> 28)) ^
                    ((s5Lsw << 30) | (s5Msw >>> 2))  ^
                    ((s5Lsw << 25) | (s5Msw >>> 7))
                );

                // sigma1
                var sigma1Msw = (
                    ((s1Lsw << 18) | (s1Msw >>> 14)) ^
                    ((s1Lsw << 14) | (s1Msw >>> 18)) ^
                    ((s1Msw << 23) | (s1Lsw >>> 9))
                );
                var sigma1Lsw = (
                    ((s1Msw << 18) | (s1Lsw >>> 14)) ^
                    ((s1Msw << 14) | (s1Lsw >>> 18)) ^
                    ((s1Lsw << 23) | (s1Msw >>> 9))
                );

                // ch + sigma1
                var t0Lsw = chLsw + sigma1Lsw;
                var t0Msw = chMsw + sigma1Msw + ((t0Lsw >>> 0) < (chLsw >>> 0) ? 1 : 0);

                // M[round] + ROUND_CONSTANTS[round]
                var t1Lsw = MRoundLsw + roundConstantLsw;
                var t1Msw = MRoundMsw + roundConstantMsw + ((t1Lsw >>> 0) < (MRoundLsw >>> 0) ? 1 : 0);

                // (ch + sigma1) + (M[round] + ROUND_CONSTANTS[round])
                var t2Lsw = t0Lsw + t1Lsw;
                var t2Msw = t0Msw + t1Msw + ((t2Lsw >>> 0) < (t0Lsw >>> 0) ? 1 : 0);

                // s4 + ((ch + sigma1) + (M[round] + ROUND_CONSTANTS[round]))
                var t3Lsw = s4Lsw + t2Lsw;
                var t3Msw = s4Msw + t2Msw + ((t3Lsw >>> 0) < (t2Lsw >>> 0) ? 1 : 0);

                // maj + sigma0
                var t4Lsw = majLsw + sigma0Lsw;
                var t4Msw = majMsw + sigma0Msw + ((t4Lsw >>> 0) < (majLsw >>> 0) ? 1 : 0);

                // Update working state
                s0Lsw = (s0Lsw + t3Lsw) | 0;
                s0Msw = (s0Msw + t3Msw + ((s0Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
                s4Lsw = (t3Lsw + t4Lsw) | 0;
                s4Msw = (t3Msw + t4Msw + ((s4Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
            }

            // Inline round 5
            {
                // Shortcuts
                var MRoundMsw = M[round + 8];
                var MRoundLsw = M[round + 9];
                var roundConstantMsw = ROUND_CONSTANTS[round + 8];
                var roundConstantLsw = ROUND_CONSTANTS[round + 9];

                // ch
                var chMsw = (s0Msw & s1Msw) ^ (~s0Msw & s2Msw);
                var chLsw = (s0Lsw & s1Lsw) ^ (~s0Lsw & s2Lsw);

                // maj
                var majMsw = (s4Msw & s5Msw) ^ (s4Msw & s6Msw) ^ (s5Msw & s6Msw);
                var majLsw = (s4Lsw & s5Lsw) ^ (s4Lsw & s6Lsw) ^ (s5Lsw & s6Lsw);

                // sigma0
                var sigma0Msw = (
                    ((s4Lsw << 4)  | (s4Msw >>> 28)) ^
                    ((s4Msw << 30) | (s4Lsw >>> 2))  ^
                    ((s4Msw << 25) | (s4Lsw >>> 7))
                );
                var sigma0Lsw = (
                    ((s4Msw << 4)  | (s4Lsw >>> 28)) ^
                    ((s4Lsw << 30) | (s4Msw >>> 2))  ^
                    ((s4Lsw << 25) | (s4Msw >>> 7))
                );

                // sigma1
                var sigma1Msw = (
                    ((s0Lsw << 18) | (s0Msw >>> 14)) ^
                    ((s0Lsw << 14) | (s0Msw >>> 18)) ^
                    ((s0Msw << 23) | (s0Lsw >>> 9))
                );
                var sigma1Lsw = (
                    ((s0Msw << 18) | (s0Lsw >>> 14)) ^
                    ((s0Msw << 14) | (s0Lsw >>> 18)) ^
                    ((s0Lsw << 23) | (s0Msw >>> 9))
                );

                // ch + sigma1
                var t0Lsw = chLsw + sigma1Lsw;
                var t0Msw = chMsw + sigma1Msw + ((t0Lsw >>> 0) < (chLsw >>> 0) ? 1 : 0);

                // M[round] + ROUND_CONSTANTS[round]
                var t1Lsw = MRoundLsw + roundConstantLsw;
                var t1Msw = MRoundMsw + roundConstantMsw + ((t1Lsw >>> 0) < (MRoundLsw >>> 0) ? 1 : 0);

                // (ch + sigma1) + (M[round] + ROUND_CONSTANTS[round])
                var t2Lsw = t0Lsw + t1Lsw;
                var t2Msw = t0Msw + t1Msw + ((t2Lsw >>> 0) < (t0Lsw >>> 0) ? 1 : 0);

                // s3 + ((ch + sigma1) + (M[round] + ROUND_CONSTANTS[round]))
                var t3Lsw = s3Lsw + t2Lsw;
                var t3Msw = s3Msw + t2Msw + ((t3Lsw >>> 0) < (t2Lsw >>> 0) ? 1 : 0);

                // maj + sigma0
                var t4Lsw = majLsw + sigma0Lsw;
                var t4Msw = majMsw + sigma0Msw + ((t4Lsw >>> 0) < (majLsw >>> 0) ? 1 : 0);

                // Update working state
                s7Lsw = (s7Lsw + t3Lsw) | 0;
                s7Msw = (s7Msw + t3Msw + ((s7Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
                s3Lsw = (t3Lsw + t4Lsw) | 0;
                s3Msw = (t3Msw + t4Msw + ((s3Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
            }

            // Inline round 6
            {
                // Shortcuts
                var MRoundMsw = M[round + 10];
                var MRoundLsw = M[round + 11];
                var roundConstantMsw = ROUND_CONSTANTS[round + 10];
                var roundConstantLsw = ROUND_CONSTANTS[round + 11];

                // ch
                var chMsw = (s7Msw & s0Msw) ^ (~s7Msw & s1Msw);
                var chLsw = (s7Lsw & s0Lsw) ^ (~s7Lsw & s1Lsw);

                // maj
                var majMsw = (s3Msw & s4Msw) ^ (s3Msw & s5Msw) ^ (s4Msw & s5Msw);
                var majLsw = (s3Lsw & s4Lsw) ^ (s3Lsw & s5Lsw) ^ (s4Lsw & s5Lsw);

                // sigma0
                var sigma0Msw = (
                    ((s3Lsw << 4)  | (s3Msw >>> 28)) ^
                    ((s3Msw << 30) | (s3Lsw >>> 2))  ^
                    ((s3Msw << 25) | (s3Lsw >>> 7))
                );
                var sigma0Lsw = (
                    ((s3Msw << 4)  | (s3Lsw >>> 28)) ^
                    ((s3Lsw << 30) | (s3Msw >>> 2))  ^
                    ((s3Lsw << 25) | (s3Msw >>> 7))
                );

                // sigma1
                var sigma1Msw = (
                    ((s7Lsw << 18) | (s7Msw >>> 14)) ^
                    ((s7Lsw << 14) | (s7Msw >>> 18)) ^
                    ((s7Msw << 23) | (s7Lsw >>> 9))
                );
                var sigma1Lsw = (
                    ((s7Msw << 18) | (s7Lsw >>> 14)) ^
                    ((s7Msw << 14) | (s7Lsw >>> 18)) ^
                    ((s7Lsw << 23) | (s7Msw >>> 9))
                );

                // ch + sigma1
                var t0Lsw = chLsw + sigma1Lsw;
                var t0Msw = chMsw + sigma1Msw + ((t0Lsw >>> 0) < (chLsw >>> 0) ? 1 : 0);

                // M[round] + ROUND_CONSTANTS[round]
                var t1Lsw = MRoundLsw + roundConstantLsw;
                var t1Msw = MRoundMsw + roundConstantMsw + ((t1Lsw >>> 0) < (MRoundLsw >>> 0) ? 1 : 0);

                // (ch + sigma1) + (M[round] + ROUND_CONSTANTS[round])
                var t2Lsw = t0Lsw + t1Lsw;
                var t2Msw = t0Msw + t1Msw + ((t2Lsw >>> 0) < (t0Lsw >>> 0) ? 1 : 0);

                // s2 + ((ch + sigma1) + (M[round] + ROUND_CONSTANTS[round]))
                var t3Lsw = s2Lsw + t2Lsw;
                var t3Msw = s2Msw + t2Msw + ((t3Lsw >>> 0) < (t2Lsw >>> 0) ? 1 : 0);

                // maj + sigma0
                var t4Lsw = majLsw + sigma0Lsw;
                var t4Msw = majMsw + sigma0Msw + ((t4Lsw >>> 0) < (majLsw >>> 0) ? 1 : 0);

                // Update working state
                s6Lsw = (s6Lsw + t3Lsw) | 0;
                s6Msw = (s6Msw + t3Msw + ((s6Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
                s2Lsw = (t3Lsw + t4Lsw) | 0;
                s2Msw = (t3Msw + t4Msw + ((s2Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
            }

            // Inline round 7
            {
                // Shortcuts
                var MRoundMsw = M[round + 12];
                var MRoundLsw = M[round + 13];
                var roundConstantMsw = ROUND_CONSTANTS[round + 12];
                var roundConstantLsw = ROUND_CONSTANTS[round + 13];

                // ch
                var chMsw = (s6Msw & s7Msw) ^ (~s6Msw & s0Msw);
                var chLsw = (s6Lsw & s7Lsw) ^ (~s6Lsw & s0Lsw);

                // maj
                var majMsw = (s2Msw & s3Msw) ^ (s2Msw & s4Msw) ^ (s3Msw & s4Msw);
                var majLsw = (s2Lsw & s3Lsw) ^ (s2Lsw & s4Lsw) ^ (s3Lsw & s4Lsw);

                // sigma0
                var sigma0Msw = (
                    ((s2Lsw << 4)  | (s2Msw >>> 28)) ^
                    ((s2Msw << 30) | (s2Lsw >>> 2))  ^
                    ((s2Msw << 25) | (s2Lsw >>> 7))
                );
                var sigma0Lsw = (
                    ((s2Msw << 4)  | (s2Lsw >>> 28)) ^
                    ((s2Lsw << 30) | (s2Msw >>> 2))  ^
                    ((s2Lsw << 25) | (s2Msw >>> 7))
                );

                // sigma1
                var sigma1Msw = (
                    ((s6Lsw << 18) | (s6Msw >>> 14)) ^
                    ((s6Lsw << 14) | (s6Msw >>> 18)) ^
                    ((s6Msw << 23) | (s6Lsw >>> 9))
                );
                var sigma1Lsw = (
                    ((s6Msw << 18) | (s6Lsw >>> 14)) ^
                    ((s6Msw << 14) | (s6Lsw >>> 18)) ^
                    ((s6Lsw << 23) | (s6Msw >>> 9))
                );

                // ch + sigma1
                var t0Lsw = chLsw + sigma1Lsw;
                var t0Msw = chMsw + sigma1Msw + ((t0Lsw >>> 0) < (chLsw >>> 0) ? 1 : 0);

                // M[round] + ROUND_CONSTANTS[round]
                var t1Lsw = MRoundLsw + roundConstantLsw;
                var t1Msw = MRoundMsw + roundConstantMsw + ((t1Lsw >>> 0) < (MRoundLsw >>> 0) ? 1 : 0);

                // (ch + sigma1) + (M[round] + ROUND_CONSTANTS[round])
                var t2Lsw = t0Lsw + t1Lsw;
                var t2Msw = t0Msw + t1Msw + ((t2Lsw >>> 0) < (t0Lsw >>> 0) ? 1 : 0);

                // s1 + ((ch + sigma1) + (M[round] + ROUND_CONSTANTS[round]))
                var t3Lsw = s1Lsw + t2Lsw;
                var t3Msw = s1Msw + t2Msw + ((t3Lsw >>> 0) < (t2Lsw >>> 0) ? 1 : 0);

                // maj + sigma0
                var t4Lsw = majLsw + sigma0Lsw;
                var t4Msw = majMsw + sigma0Msw + ((t4Lsw >>> 0) < (majLsw >>> 0) ? 1 : 0);

                // Update working state
                s5Lsw = (s5Lsw + t3Lsw) | 0;
                s5Msw = (s5Msw + t3Msw + ((s5Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
                s1Lsw = (t3Lsw + t4Lsw) | 0;
                s1Msw = (t3Msw + t4Msw + ((s1Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
            }

            // Inline round 8
            {
                // Shortcuts
                var MRoundMsw = M[round + 14];
                var MRoundLsw = M[round + 15];
                var roundConstantMsw = ROUND_CONSTANTS[round + 14];
                var roundConstantLsw = ROUND_CONSTANTS[round + 15];

                // ch
                var chMsw = (s5Msw & s6Msw) ^ (~s5Msw & s7Msw);
                var chLsw = (s5Lsw & s6Lsw) ^ (~s5Lsw & s7Lsw);

                // maj
                var majMsw = (s1Msw & s2Msw) ^ (s1Msw & s3Msw) ^ (s2Msw & s3Msw);
                var majLsw = (s1Lsw & s2Lsw) ^ (s1Lsw & s3Lsw) ^ (s2Lsw & s3Lsw);

                // sigma0
                var sigma0Msw = (
                    ((s1Lsw << 4)  | (s1Msw >>> 28)) ^
                    ((s1Msw << 30) | (s1Lsw >>> 2))  ^
                    ((s1Msw << 25) | (s1Lsw >>> 7))
                );
                var sigma0Lsw = (
                    ((s1Msw << 4)  | (s1Lsw >>> 28)) ^
                    ((s1Lsw << 30) | (s1Msw >>> 2))  ^
                    ((s1Lsw << 25) | (s1Msw >>> 7))
                );

                // sigma1
                var sigma1Msw = (
                    ((s5Lsw << 18) | (s5Msw >>> 14)) ^
                    ((s5Lsw << 14) | (s5Msw >>> 18)) ^
                    ((s5Msw << 23) | (s5Lsw >>> 9))
                );
                var sigma1Lsw = (
                    ((s5Msw << 18) | (s5Lsw >>> 14)) ^
                    ((s5Msw << 14) | (s5Lsw >>> 18)) ^
                    ((s5Lsw << 23) | (s5Msw >>> 9))
                );

                // ch + sigma1
                var t0Lsw = chLsw + sigma1Lsw;
                var t0Msw = chMsw + sigma1Msw + ((t0Lsw >>> 0) < (chLsw >>> 0) ? 1 : 0);

                // M[round] + ROUND_CONSTANTS[round]
                var t1Lsw = MRoundLsw + roundConstantLsw;
                var t1Msw = MRoundMsw + roundConstantMsw + ((t1Lsw >>> 0) < (MRoundLsw >>> 0) ? 1 : 0);

                // (ch + sigma1) + (M[round] + ROUND_CONSTANTS[round])
                var t2Lsw = t0Lsw + t1Lsw;
                var t2Msw = t0Msw + t1Msw + ((t2Lsw >>> 0) < (t0Lsw >>> 0) ? 1 : 0);

                // s0 + ((ch + sigma1) + (M[round] + ROUND_CONSTANTS[round]))
                var t3Lsw = s0Lsw + t2Lsw;
                var t3Msw = s0Msw + t2Msw + ((t3Lsw >>> 0) < (t2Lsw >>> 0) ? 1 : 0);

                // maj + sigma0
                var t4Lsw = majLsw + sigma0Lsw;
                var t4Msw = majMsw + sigma0Msw + ((t4Lsw >>> 0) < (majLsw >>> 0) ? 1 : 0);

                // Update working state
                s4Lsw = (s4Lsw + t3Lsw) | 0;
                s4Msw = (s4Msw + t3Msw + ((s4Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
                s0Lsw = (t3Lsw + t4Lsw) | 0;
                s0Msw = (t3Msw + t4Msw + ((s0Lsw >>> 0) < (t3Lsw >>> 0) ? 1 : 0)) | 0;
            }
        }

        // Update state
        _s0Lsw = s[1] = (_s0Lsw + s0Lsw) | 0;
        s[0] = (_s0Msw + s0Msw + ((_s0Lsw >>> 0) < (s0Lsw >>> 0) ? 1 : 0)) | 0;
        _s1Lsw = s[3] = (_s1Lsw + s1Lsw) | 0;
        s[2] = (_s1Msw + s1Msw + ((_s1Lsw >>> 0) < (s1Lsw >>> 0) ? 1 : 0)) | 0;
        _s2Lsw = s[5] = (_s2Lsw + s2Lsw) | 0;
        s[4] = (_s2Msw + s2Msw + ((_s2Lsw >>> 0) < (s2Lsw >>> 0) ? 1 : 0)) | 0;
        _s3Lsw = s[7] = (_s3Lsw + s3Lsw) | 0;
        s[6] = (_s3Msw + s3Msw + ((_s3Lsw >>> 0) < (s3Lsw >>> 0) ? 1 : 0)) | 0;
        _s4Lsw = s[9] = (_s4Lsw + s4Lsw) | 0;
        s[8] = (_s4Msw + s4Msw + ((_s4Lsw >>> 0) < (s4Lsw >>> 0) ? 1 : 0)) | 0;
        _s5Lsw = s[11] = (_s5Lsw + s5Lsw) | 0;
        s[10] = (_s5Msw + s5Msw + ((_s5Lsw >>> 0) < (s5Lsw >>> 0) ? 1 : 0)) | 0;
        _s6Lsw = s[13] = (_s6Lsw + s6Lsw) | 0;
        s[12] = (_s6Msw + s6Msw + ((_s6Lsw >>> 0) < (s6Lsw >>> 0) ? 1 : 0)) | 0;
        _s7Lsw = s[15] = (_s7Lsw + s7Lsw) | 0;
        s[14] = (_s7Msw + s7Msw + ((_s7Lsw >>> 0) < (s7Lsw >>> 0) ? 1 : 0)) | 0;
      }

      return kryptos.fromByteArray(kryptos.wordsToBytes(s));
    }
  };
}
