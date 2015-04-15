kryptos = function() {};
kryptos.prototype = {};

kryptos.cipher    = {};
kryptos.hash      = {};
kryptos.protocol  = {};
kryptos.publicKey = {};
kryptos.random    = {};
kryptos.random.Fortuna = {};
kryptos.random.OSRNG = {};
kryptos.util      = {};

kryptos.toByteArray = function(str) {
  function charToUint(chr) { return chr.charCodeAt(0) }
  return str.split('').map(charToUint);
};

kryptos.fromByteArray = function(data) {
  function uintToChar(uint) { return String.fromCharCode(uint) }
  return data.map(uintToChar).join('');
};

kryptos.bytesToWords = function(bytes) {
  for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8) {
    words[b >>> 5] |= (bytes[i] & 0xFF) << (24 - b % 32);
  }
  return words;
};

kryptos.wordsToBytes = function(words) {
  for (var bytes = [], b = 0; b < words.length * 32; b += 8) {
    bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
  }
  return bytes;
};


kryptos.heap32Set = function(dest, source, offset, opt_limit) {
  var limit = opt_limit || 65536;
  for (var i = 0, o = offset; i < source.length && i < limit; i++, o++) {
    dest[o] = source[i];
  }
  //dest.set(source, offset);
};

kryptos.heap32SetStr = function(dest, source, offset) {
  for (var i = 0, o = offset; i < source.length; i++, o++) {
    dest[o] = source.charCodeAt(i);
  }
};

kryptos.heap32GetStr = function(heap, start, end) {
  return String.fromCharCode.apply(null, heap.subarray(start, end));
};
