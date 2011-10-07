crypto.hash.SHA256 = function(str) {
  inherit(this, new crypto.hash.baseHash(str));
}

crypto.hash.SHA256.digest_size = 32;

crypto.hash.SHA256.prototype = {
  type : 'sha256'
};
