kryptos.random.Fortuna.SHAd256 = function(str) {
  inherit(this, new kryptos.hash.baseHash(str));
}

kryptos.random.Fortuna.SHAd256.digest_size = 32;

kryptos.random.Fortuna.SHAd256.prototype = {
  type : 'sha256',

  digest : function() {
    return new kryptos.hash.SHA256(new kryptos.hash.SHA256(this.data).digest()).digest();
  }
};
