if (navigator.userAgent.toLowerCase().indexOf('chrome') == -1) { // Mozilla
  crypto = function() {};

  crypto.prototype = {
    
  };
}

crypto.cipher    = {};
crypto.hash      = {};
crypto.protocol  = {};
crypto.publicKey = {};
crypto.random    = {};
crypto.random.Fortuna = {};
crypto.random.OSRNG = {};
crypto.util      = {};

crypto.toByteArray = function(str) {
  function charToUint(chr) { return chr.charCodeAt(0) }
  return str.split('').map(charToUint);
};

crypto.fromByteArray = function(data) {
  function uintToChar(uint) { return String.fromCharCode(uint) }
  return data.map(uintToChar).join('');
};

crypto.bytesToWords = function(bytes) {
  for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8) {
    words[b >>> 5] |= (bytes[i] & 0xFF) << (24 - b % 32);
  }
  return words;
};

crypto.wordsToBytes = function(words) {
  for (var bytes = [], b = 0; b < words.length * 32; b += 8) {
    bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
  }
  return bytes;
};
