crypto.hash.HMAC = function(key, msg, digestmod) {
  var hasher = Components.classes["@mozilla.org/security/hmac;1"].createInstance(Components.interfaces.nsICryptoHMAC);
  var keyObject = Components.classes["@mozilla.org/security/keyobjectfactory;1"]
                    .getService(Components.interfaces.nsIKeyObjectFactory)
                    .keyFromString(Components.interfaces.nsIKeyObject.HMAC, key);
  
  hasher.init(digestmod, keyObject);
  var data = crypto.toByteArray(msg);
  hasher.update(data, data.length);
  return hasher.finish(false);
}

crypto.hash.HMAC_SHA = Components.classes["@mozilla.org/security/hmac;1"].createInstance(Components.interfaces.nsICryptoHMAC).SHA1;
crypto.hash.HMAC_MD5 = Components.classes["@mozilla.org/security/hmac;1"].createInstance(Components.interfaces.nsICryptoHMAC).MD5;

