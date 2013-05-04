kryptos.publicKey.DSA = function() {
  
}

kryptos.publicKey.DSA.prototype = {
  construct : function(y, g, p, q, x) {
    this.y = y;
    this.g = g;
    this.p = p;
    this.q = q;
    this.x = x;

    return this;
  },

  sign : function(m, k) {
    // SECURITY TODO - We _should_ be computing SHA1(m), but we don't because that's the API.
    var one = BigInteger.ONE;
    if (!(k.compareTo(one) > 0 && this.q.compareTo(k) > 0)) {
      throw "k is not between 2 and q-1";
    }
    var inv_k = k.modInverse(this.q);   // Compute k**-1 mod q
    var r = this.g.modPow(k, this.p).mod(this.q);  // r = (g**k mod p) mod q
    var s = inv_k.multiply(m.add(this.x.multiply(r))).mod(this.q);
    return [r, s];
  },

  verify : function(m, sig) {
    var r = sig[0];
    var s = sig[1];
    var zero = BigInteger.ZERO;
    // SECURITY TODO - We _should_ be computing SHA1(m), but we don't because that's the API.
    if (!(r.compareTo(zero) > 0 && this.q.compareTo(r) > 0) || !(s.compareTo(zero) > 0 && this.q.compareTo(s) > 0)) {
      return false;
    }
    var w = s.modInverse(this.q);
    var u1 = m.multiply(w).mod(this.q);
    var u2 = r.multiply(w).mod(this.q);
    var v = this.g.modPow(u1, this.p).multiply(this.y.modPow(u2, this.p)).mod(this.p).mod(this.q);
    return v.equals(r);
  },

  generate : function() {
    alert('NOT_IMPLEMENTED');
  }
};
