Components.utils.import("resource://services-sync/util.js");

kryptos.cipher.nss3 = function(key, algorithm, mode, iv, counter) {
  this.key = base64.encodestring(key);
  this.algorithm = algorithm;
  this.mode = mode;
  this.iv = base64.encodestring(iv);
  this.counter = counter;

  this.cryptoSvc = Svc.Crypto;
  this.cryptoSvc.algorithm = this.algorithm;
}

kryptos.cipher.nss3.MODE_CBC = 2;
kryptos.cipher.nss3.MODE_CTR = 6;

kryptos.cipher.nss3.RC4_128 = 154;
kryptos.cipher.nss3.DES_EDE3_CBC = 156;
kryptos.cipher.nss3.AES_128_CBC = 184;
kryptos.cipher.nss3.AES_256_CBC = 188;

// todo counter
kryptos.cipher.nss3.prototype = {
  encrypt : function(plaintext) {
    var ciphertext = base64.decodestring(this.cryptoSvc.encrypt(plaintext, this.key, this.iv));
    if (this.mode == kryptos.cipher.nss3.MODE_CBC) {
      this.iv = base64.encodestring(ciphertext.slice(-16));
    }
    return ciphertext;
  },

  decrypt : function(ciphertext) {
    ciphertext = kryptos.toByteArray(ciphertext);
    if (this.mode == kryptos.cipher.nss3.MODE_CBC) {
      var plaintext = this.cipher.decrypt(ciphertext, this.iv);
      this.iv = ciphertext.slice(-16);
    } else {
      var plaintext = this.cipher.encrypt(ciphertext, this.iv, this.counter);
    }
    return kryptos.fromByteArray(plaintext);
  }
};
