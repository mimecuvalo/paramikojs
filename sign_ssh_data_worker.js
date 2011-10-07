importScripts('chrome://fireftp/content/js/connection/paramikojs/crypto/crypto.js',
              'chrome://fireftp/content/js/connection/paramikojs/crypto/PublicKey/RSA.js',
              'chrome://fireftp/content/js/connection/paramikojs/common.js',
              'chrome://fireftp/content/js/connection/paramikojs/python_shim.js',
              'chrome://fireftp/content/js/connection/paramikojs/BigInteger.js',
              'chrome://fireftp/content/js/connection/paramikojs/util.js');

onmessage = function(event) {
  var rsa = new crypto.publicKey.RSA().construct(new BigInteger(event.data.n, 10),
                                                 new BigInteger(event.data.e, 10),
                                                 new BigInteger(event.data.d, 10));
  var inflated = paramikojs.util.inflate_long(event.data.pkcs1imified, true);
  postMessage(rsa.sign(inflated, '')[0].toString());
};
