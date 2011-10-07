crypto.random.Fortuna.SHAd256 = function(str) {
  inherit(this, new crypto.hash.baseHash(str));
}

crypto.random.Fortuna.SHAd256.digest_size = 32;

crypto.random.Fortuna.SHAd256.prototype = {
  type : 'sha256',

  digest : function() {
    return new crypto.hash.SHA256(new crypto.hash.SHA256(this.data).digest()).digest();
  }
};
