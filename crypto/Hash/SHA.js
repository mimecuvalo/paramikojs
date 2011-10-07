crypto.hash.SHA = function(str) {
  inherit(this, new crypto.hash.baseHash(str));
}

crypto.hash.SHA.digest_size = 20;

crypto.hash.SHA.prototype = {
  type : 'sha1'
};
