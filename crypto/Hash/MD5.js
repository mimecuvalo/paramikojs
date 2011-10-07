crypto.hash.MD5 = function(str) {
  inherit(this, new crypto.hash.baseHash(str));
}

crypto.hash.MD5.digest_size = 16;

crypto.hash.MD5.prototype = {
  type : 'md5'
};
