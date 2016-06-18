/*
  Copyright (C) 2013  Torsten Landschoff <torsten@debian.org>

  Standard SSH key exchange ("kex" if you wanna sound cool).  Diffie-Hellman of
  2048 bit key halves, using a known "p" prime and "g" generator.
*/

paramikojs.KexGroup14 = function(transport) {
  inherit(this, new paramikojs.KexGroup1(transport));

  this.P = paramikojs.KexGroup14.P;
  this.G = paramikojs.KexGroup14.G;
  this.hash_algo = kryptos.hash.SHA;
}

// http://tools.ietf.org/html/rfc3526#section-3
paramikojs.KexGroup14.P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
paramikojs.KexGroup14.G = new BigInteger("2", 10);

paramikojs.KexGroup14.prototype = {
  name : 'diffie-hellman-group14-sha1'
};
