if (Components && Components.classes) { // Mozilla extension
  kryptos.hash.HMAC = function(key, msg, digestmod) {
    var hasher = Components.classes["@mozilla.org/security/hmac;1"].createInstance(Components.interfaces.nsICryptoHMAC);
    var keyObject = Components.classes["@mozilla.org/security/keyobjectfactory;1"]
                      .getService(Components.interfaces.nsIKeyObjectFactory)
                      .keyFromString(Components.interfaces.nsIKeyObject.HMAC, key);
    
    hasher.init(digestmod, keyObject);
    var data = kryptos.toByteArray(msg);
    hasher.update(data, data.length);
    return hasher.finish(false);
  };

  kryptos.hash.HMAC_SHA = Components.classes["@mozilla.org/security/hmac;1"].createInstance(Components.interfaces.nsICryptoHMAC).SHA1;
  kryptos.hash.HMAC_SHA256 = Components.classes["@mozilla.org/security/hmac;1"].createInstance(Components.interfaces.nsICryptoHMAC).SHA256;
  kryptos.hash.HMAC_SHA512 = Components.classes["@mozilla.org/security/hmac;1"].createInstance(Components.interfaces.nsICryptoHMAC).SHA512;
  kryptos.hash.HMAC_MD5 = Components.classes["@mozilla.org/security/hmac;1"].createInstance(Components.interfaces.nsICryptoHMAC).MD5;
} else {  // Chrome or plain Mozilla
  kryptos.hash.HMAC = function(key, msg, digestmod) {
    var blocksize = 64;
    var ipad = 0x36;
    var opad = 0x5C;

    var hasher;
    switch (digestmod) {
      case 2:
        hasher = kryptos.hash.MD5;
        break;
      case 3:
        hasher = kryptos.hash.SHA;
        break;
      case 4:
        hasher = kryptos.hash.SHA256;
        break;
      case 6:
        hasher = kryptos.hash.SHA512;
        blocksize = 128;
        break;
    }

    var outer = new hasher();
    var inner = new hasher();

    if (key.length > blocksize) {
      key = new hasher(key).digest();
    }

    key = key + new Array(blocksize - key.length + 1).join('\x00');

    var okey = kryptos.toByteArray(key).slice(0);
    var ikey = kryptos.toByteArray(key).slice(0);

    for (var x = 0; x < blocksize; ++x) {
      okey[x] ^= opad;
      ikey[x] ^= ipad;
    }

    outer.update(okey);
    inner.update(ikey);
    inner.update(msg);
    outer.update(inner.digest());
    return outer.digest();
  };
  kryptos.hash.HMAC_SHA = 3;
  kryptos.hash.HMAC_SHA256 = 4;
  kryptos.hash.HMAC_SHA512 = 6;
  kryptos.hash.HMAC_MD5 = 2;
}
