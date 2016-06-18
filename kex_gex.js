/*
  Variant on L{KexGroup1 <paramiko.kex_group1.KexGroup1>} where the prime "p" and
  generator "g" are provided by the server.  A bit more work is required on the
  client side, and a B{lot} more on the server side.
*/

paramikojs.KexGex = function(transport) {
  this.transport = transport;
  this.p = null;
  this.q = null;
  this.g = null;
  this.x = null;
  this.e = null;
  this.f = null;
  this.old_style = false;
  this.hash_algo = kryptos.hash.SHA;
}


paramikojs.KexGex._MSG_KEXDH_GEX_REQUEST_OLD = 30;
paramikojs.KexGex._MSG_KEXDH_GEX_GROUP = 31;
paramikojs.KexGex._MSG_KEXDH_GEX_INIT = 32;
paramikojs.KexGex._MSG_KEXDH_GEX_REPLY = 33;
paramikojs.KexGex._MSG_KEXDH_GEX_REQUEST = 34;

paramikojs.KexGex.prototype = {
  name : 'diffie-hellman-group-exchange-sha1',
  min_bits : 1024,
  max_bits : 8192,
  preferred_bits : 2048,

  start_kex : function(_test_old_style) {
    if (this.transport.server_mode) {
      this.transport._expect_packet(paramikojs.KexGex._MSG_KEXDH_GEX_REQUEST, paramikojs.KexGex._MSG_KEXDH_GEX_REQUEST_OLD);
      return;
    }
    // request a bit range: we accept (min_bits) to (max_bits), but prefer
    // (preferred_bits).  according to the spec, we shouldn't pull the
    // minimum up above 1024.
    var m = new paramikojs.Message();
    if (_test_old_style) {
      // only used for unit tests: we shouldn't ever send this
      m.add_byte(String.fromCharCode(paramikojs.KexGex._MSG_KEXDH_GEX_REQUEST_OLD));
      m.add_int(this.preferred_bits);
      this.old_style = true;
    } else {
      m.add_byte(String.fromCharCode(paramikojs.KexGex._MSG_KEXDH_GEX_REQUEST));
      m.add_int(this.min_bits);
      m.add_int(this.preferred_bits);
      m.add_int(this.max_bits);
    }
    this.transport._send_message(m);
    this.transport._expect_packet(paramikojs.KexGex._MSG_KEXDH_GEX_GROUP);
  },

  parse_next : function(ptype, m) {
    if (ptype == paramikojs.KexGex._MSG_KEXDH_GEX_GROUP) {
      return this._parse_kexdh_gex_group(m);
    } else if (ptype == paramikojs.KexGex._MSG_KEXDH_GEX_REPLY) {
      return this._parse_kexdh_gex_reply(m);
    }
    throw new paramikojs.ssh_exception.SSHException('KexGex asked to handle packet type ' + ptype);
  },


  //  internals...

  _generate_x : function() {
    // generate an "x" (1 < x < (p-1)/2).
    var one = BigInteger.ONE;
    var q = this.p.subtract(one);
    q = q.divide(new BigInteger("2", 10));
    var qnorm = paramikojs.util.deflate_long(q, 0);
    var qhbyte = qnorm[0].charCodeAt(0);
    var bytes = qnorm.length;
    var qmask = 0xff;
    while (!(qhbyte & 0x80)) {
      qhbyte <<= 1;
      qmask >>= 1;
    }
    var x;
    while (true) {
      var x_bytes = this.transport.rng.read(bytes);
      x_bytes = String.fromCharCode(x_bytes[0].charCodeAt(0) & qmask) + x_bytes.substring(1);
      x = paramikojs.util.inflate_long(x_bytes, 1);
      if (x.compareTo(one) > 0 && q.compareTo(x) > 0) {
        break;
      }
    }
    this.x = x;
  },

  _parse_kexdh_gex_group : function(m) {
    this.p = m.get_mpint();
    this.g = m.get_mpint();
    // reject if p's bit length < 1024 or > 8192
    var bitlen = paramikojs.util.bit_length(this.p);
    if (bitlen < 1024 || bitlen > 8192) {
      throw new paramikojs.ssh_exception.SSHException('Server-generated gex p (don\'t ask) is out of range (' + bitlen + ' bits)');
    }
    this.transport._log(DEBUG, 'Got server p (' + bitlen + ' bits)');
    this._generate_x();
    // now compute e = g^x mod p
    this.e = this.g.modPow(this.x, this.p);
    m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.KexGex._MSG_KEXDH_GEX_INIT));
    m.add_mpint(this.e);
    this.transport._send_message(m);
    this.transport._expect_packet(paramikojs.KexGex._MSG_KEXDH_GEX_REPLY);
  },
    
  _parse_kexdh_gex_reply : function(m) {
    var host_key = m.get_string();
    this.f = m.get_mpint();
    var sig = m.get_string();
    var one = BigInteger.ONE;
    if (one.compareTo(this.f) > 0 || this.f.compareTo(this.p.subtract(one)) > 0) {
      throw new paramikojs.ssh_exception.SSHException('Server kex "f" is out of range');
    }
    var K = this.f.modPow(this.x, this.p);
    // okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || min || n || max || p || g || e || f || K)
    var hm = new paramikojs.Message();
    hm.add(this.transport.local_version, this.transport.remote_version,
           this.transport.local_kex_init, this.transport.remote_kex_init,
           host_key);
    if (!this.old_style) {
      hm.add_int(this.min_bits);
    }
    hm.add_int(this.preferred_bits);
    if (!this.old_style) {
      hm.add_int(this.max_bits);
    }
    hm.add_mpint(this.p);
    hm.add_mpint(this.g);
    hm.add_mpint(this.e);
    hm.add_mpint(this.f);
    hm.add_mpint(K);
    this.transport._set_K_H(K, new this.hash_algo(hm.toString()).digest());
    this.transport._verify_key(host_key, sig);
    this.transport._activate_outbound();
  }
};

paramikojs.KexGexSHA256 = function(transport) {
  inherit(this, new paramikojs.KexGex(transport));
  this.name = 'diffie-hellman-group-exchange-sha256';
  this.hash_algo = kryptos.hash.SHA256;
};
