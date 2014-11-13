/*
  Representation of a DSS key which can be used to sign and verify SSH2
  data.
*/
paramikojs.DSSKey = function(msg, data, filename, password, vals, file_obj) {
  inherit(this, new paramikojs.PKey());

  this.p = null;
  this.q = null;
  this.g = null;
  this.y = null;
  this.x = null;
  if (file_obj) {
    this._from_private_key(file_obj, password);
    return;
  }
  if (filename) {
    this._from_private_key_file(filename, password);
    return;
  }
  if (!msg && data) {
    msg = new paramikojs.Message(data);
  }
  if (vals) {
    this.p = vals[0];
    this.q = vals[1];
    this.g = vals[2];
    this.y = vals[3];
  } else {
    if (!msg) {
      throw new paramikojs.ssh_exception.SSHException('Key object may not be empty');
    }
    if (msg.get_string() != 'ssh-dss') {
      throw new paramikojs.ssh_exception.SSHException('Invalid key');
    }
    this.p = msg.get_mpint();
    this.q = msg.get_mpint();
    this.g = msg.get_mpint();
    this.y = msg.get_mpint();
  }
  this.size = paramikojs.util.bit_length(this.p);
}

paramikojs.DSSKey.prototype = {
  toString : function() {
    var m = new paramikojs.Message();
    m.add_string('ssh-dss');
    m.add_mpint(this.p);
    m.add_mpint(this.q);
    m.add_mpint(this.g);
    m.add_mpint(this.y);
    return m.toString();
  },

  compare : function(other) {
    if (this.get_name() != other.get_name()) {
      return false;
    }
    if (!this.p.equals(other.p)) {
      return false;
    }
    if (!this.q.equals(other.q)) {
      return false;
    }
    if (!this.g.equals(other.g)) {
      return false;
    }
    if (!this.y.equals(other.y)) {
      return false;
    }
    return true;
  },

  get_name : function() {
    return 'ssh-dss';
  },

  get_bits : function() {
    return this.size;
  },

  can_sign : function() {
    return this.x != null;
  },

  sign_ssh_data : function(rng, data, callback) {
    var digest = new kryptos.hash.SHA(data).digest();
    var dss = new kryptos.publicKey.DSA().construct(this.y, this.g, this.p, this.q, this.x);
    // generate a suitable k
    var qsize = paramikojs.util.deflate_long(this.q, 0).length;
    var k;
    var two = new BigInteger("2", 10);
    while (true) {
      k = paramikojs.util.inflate_long(rng.read(qsize), 1);
      if (k.compareTo(two) > 0 && this.q.compareTo(k) > 0) {
        break;
      }
    }
    var result = dss.sign(paramikojs.util.inflate_long(digest, 1), k);
    var m = new paramikojs.Message();
    m.add_string('ssh-dss');
    // apparently, in rare cases, r or s may be shorter than 20 bytes!
    var rstr = paramikojs.util.deflate_long(result[0], 0);
    var sstr = paramikojs.util.deflate_long(result[1], 0);
    if (rstr.length < 20) {
      rstr = new Array(20 - rstr.length + 1).join('\x00') + rstr;
    }
    if (sstr.length < 20) {
      sstr = new Array(20 - rstr.length + 1).join('\x00') + sstr;
    }
    m.add_string(rstr + sstr);
    callback(m);
  },

  verify_ssh_sig : function(data, msg) {
    var sig;
    var kind;
    if (msg.toString().length == 40) {
      // spies.com bug: signature has no header
      sig = msg.toString();
    } else {
      kind = msg.get_string();
      if (kind != 'ssh-dss') {
        return 0;
      }
      sig = msg.get_string();
    }

    // pull out (r, s) which are NOT encoded as mpints
    var sigR = paramikojs.util.inflate_long(sig.substring(0, 20), 1);
    var sigS = paramikojs.util.inflate_long(sig.substring(20), 1);
    var sigM = paramikojs.util.inflate_long(new kryptos.hash.SHA(data).digest(), 1);

    var dss = new kryptos.publicKey.DSA().construct(this.y, this.g, this.p, this.q);
    return dss.verify(sigM, [sigR, sigS]);
  },

  _encode_key : function() {
    if (!this.x) {
      throw new paramikojs.ssh_exception.SSHException('Not enough key information');
    }
    var keylist = [ 0, this.p, this.q, this.g, this.y, this.x ];
    var b;
    try {
        b = new paramikojs.BER();
        b.encode(keylist);
    } catch(ex) {
      throw new paramikojs.ssh_exception.SSHException('Unable to create ber encoding of key');
    }
    return b.toString();
  },

  write_private_key_file : function(filename, password) {
    this._write_private_key_file('DSA', filename, this._encode_key(), password);
  },

  write_private_key : function(file_obj, password) {
    this._write_private_key('DSA', file_obj, this._encode_key(), password);
  },

  /*
    Generate a new private DSS key.  This factory function can be used to
    generate a new host key or authentication key.

    @param bits: number of bits the generated key should be.
    @type bits: int
    @param progress_func: an optional function to call at key points in
        key generation (used by C{pyCrypto.PublicKey}).
    @type progress_func: function
    @return: new private key
    @rtype: L{DSSKey}
  */
  generate : function(bits, progress_func) {
    bits = bits || 1024;
    var dsa = new kryptos.publicKey.DSA().generate(bits, paramikojs.rng.read, progress_func);
    var key = new paramikojs.DSSKey(null, null, null, null, [dsa.p, dsa.q, dsa.g, dsa.y], null);
    key.x = dsa.x;
    return key;
  },


  //  internals...


  _from_private_key_file : function(filename, password) {
    var data;
    var keylist = null;
    try {
      data = this._read_private_key_file('DSA', filename, password);
    } catch (ex) {
      if (ex instanceof paramikojs.ssh_exception.IsPuttyKey) {
        data = null;
        keylist = this._read_putty_private_key('DSA', ex.lines, password);
      } else {
        throw ex;
      }
    }
    this._decode_key(data, keylist);
  },

  _from_private_key : function(file_obj, password) {
    var data = this._read_private_key('DSA', file_obj, password);
    this._decode_key(data);
  },

  _decode_key : function(data, keylist) {
    // private key file contains:
    // DSAPrivateKey = { version = 0, p, q, g, y, x }
    try {
      keylist = keylist || new paramikojs.BER(data).decode();
    } catch(ex) {
      throw new paramikojs.ssh_exception.SSHException('Unable to parse key file');
    }
    if (!(keylist instanceof Array) || keylist.length < 6 || keylist[0] != 0) {
      throw new paramikojs.ssh_exception.SSHException('not a valid DSA private key file (bad ber encoding)');
    }
    this.p = keylist[1];
    this.q = keylist[2];
    this.g = keylist[3];
    this.y = keylist[4];
    this.x = keylist[5];
    this.size = paramikojs.util.bit_length(this.p);
  }
};
