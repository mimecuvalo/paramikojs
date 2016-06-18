/*
  Standard SSH key exchange ("kex" if you wanna sound cool).  Diffie-Hellman of
  1024 bit key halves, using a known "p" prime and "g" generator.
*/

paramikojs.KexGroup1 = function(transport) {
  this.transport = transport;
  this.x = new BigInteger("0", 10);
  this.e = new BigInteger("0", 10);
  this.f = new BigInteger("0", 10);

  this.P = paramikojs.KexGroup1.P;
  this.G = paramikojs.KexGroup1.G;
  this.hash_algo = kryptos.hash.SHA;
}

paramikojs.KexGroup1._MSG_KEXDH_INIT = 30;
paramikojs.KexGroup1._MSG_KEXDH_REPLY = 31;

// draft-ietf-secsh-transport-09.txt, page 17
paramikojs.KexGroup1.P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16);
paramikojs.KexGroup1.G = new BigInteger("2", 10);

paramikojs.KexGroup1.prototype = {
  name : 'diffie-hellman-group1-sha1',

  start_kex : function() {
    this._generate_x();
    if (this.transport.server_mode) {
      // compute f = g^x mod p, but don't send it yet
      this.f = this.G.modPow(this.x, this.P);
      this.transport._expect_packet(paramikojs.KexGroup1._MSG_KEXDH_INIT);
      return;
    }
    // compute e = g^x mod p (where g=2), and send it
    this.e = this.G.modPow(this.x, this.P);
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.KexGroup1._MSG_KEXDH_INIT));
    m.add_mpint(this.e);
    this.transport._send_message(m);
    this.transport._expect_packet(paramikojs.KexGroup1._MSG_KEXDH_REPLY);
  },

  parse_next : function(ptype, m) {
    if (this.transport.server_mode && ptype == paramikojs.KexGroup1._MSG_KEXDH_INIT) {
      return this._parse_kexdh_init(m);
    } else if (!this.transport.server_mode && ptype == paramikojs.KexGroup1._MSG_KEXDH_REPLY) {
      return this._parse_kexdh_reply(m);
    }
    throw new paramikojs.ssh_exception.SSHException('KexGroup1 asked to handle packet type ' + ptype);
  },


  //  internals...

  _generate_x : function() {
    // generate an "x" (1 < x < q), where q is (p-1)/2.
    // p is a 128-byte (1024-bit) number, where the first 64 bits are 1. 
    // therefore q can be approximated as a 2^1023.  we drop the subset of
    // potential x where the first 63 bits are 1, because some of those will be
    // larger than q (but this is a tiny tiny subset of potential x).
    var x_bytes;
    while (true) {
      x_bytes = this.transport.rng.read(128);
      x_bytes = String.fromCharCode(x_bytes[0].charCodeAt(0) & 0x7f) + x_bytes.substring(1);
      if (x_bytes.substring(0, 8) != '\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF' && x_bytes.substring(0, 8) != '\x00\x00\x00\x00\x00\x00\x00\x00') {
        break;
      }
    }
    this.x = paramikojs.util.inflate_long(x_bytes, false);
  },

  _parse_kexdh_reply : function(m) {
    // client mode
    var host_key = m.get_string();
    this.f = m.get_mpint();
    var one = BigInteger.ONE;
    if (one.compareTo(this.f) > 0 || this.f.compareTo(this.P.subtract(one)) > 0) {
      throw new paramikojs.ssh_exception.SSHException('Server kex "f" is out of range');
    }
    var sig = m.get_string();
    var K = this.f.modPow(this.x, this.P);
    // okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || e || f || K)
    var hm = new paramikojs.Message();
    hm.add(this.transport.local_version, this.transport.remote_version,
           this.transport.local_kex_init, this.transport.remote_kex_init);
    hm.add_string(host_key);
    hm.add_mpint(this.e);
    hm.add_mpint(this.f);
    hm.add_mpint(K);
    this.transport._set_K_H(K, new kryptos.hash.SHA(hm.toString()).digest());
    this.transport._verify_key(host_key, sig);
    this.transport._activate_outbound();
  }

};
