kryptos.hash.SHA512 = function(str) {
  inherit(this, new kryptos.hash.baseHash(str));
}

kryptos.hash.SHA512.digest_size = 64;

kryptos.hash.SHA512.prototype = {
  type : 'sha512'
};
