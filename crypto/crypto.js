function crypto() {}

crypto.prototype = {
  
};

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
}

crypto.fromByteArray = function(data) {
  function uintToChar(uint) { return String.fromCharCode(uint) }
  return data.map(uintToChar).join('');
}
