/*
  Representation of an RSA key which can be used to sign and verify SSH2
  data.
*/
paramikojs.RSAKey = function(msg, data, filename, password, vals, file_obj) {
  inherit(this, new paramikojs.PKey());

  this.n = null;
  this.e = null;
  this.d = null;
  this.p = null;
  this.q = null;
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
    this.e = vals[0];
    this.n = vals[1];
  } else {
    if (!msg) {
      throw new paramikojs.ssh_exception.SSHException('Key object may not be empty');
    }
    if (msg.get_string() != 'ssh-rsa') {
      throw new paramikojs.ssh_exception.SSHException('Invalid key');
    }
    this.e = msg.get_mpint();
    this.n = msg.get_mpint();
  }
  this.size = paramikojs.util.bit_length(this.n);
}

paramikojs.RSAKey.prototype = {
  toString : function () {
    var m = new paramikojs.Message();
    m.add_string('ssh-rsa');
    m.add_mpint(this.e);
    m.add_mpint(this.n);
    return m.toString();
  },

  compare : function(other) {
    if (this.get_name() != other.get_name()) {
      return false;
    }
    if (!this.e.equals(other.e)) {
      return false;
    }
    if (!this.n.equals(other.n)) {
      return false;
    }
    return true;
  },

  get_name : function() {
    return 'ssh-rsa';
  },

  get_bits : function() {
    return this.size;
  },

  can_sign : function() {
    return this.d != null;
  },

  sign_ssh_data : function(rpool, data, callback) {
    var digest = new kryptos.hash.SHA(data).digest();
    var pkcs1imified = this._pkcs1imify(digest);

    // XXX well, ain't this some shit.  We have to use gRsaKeyWorkerJs b/c
    // the relative url won't work if we have ssh:// or sftp:// as the url instead of chrome://
    // AAARRRGH
    // var worker = new Worker('./js/connection/paramikojs/sign_ssh_data_worker.js');
    var worker = new Worker(gRsaKeyWorkerJs);
    worker.onmessage = function(event) {
      var m = new paramikojs.Message();
      m.add_string('ssh-rsa');
      m.add_string(paramikojs.util.deflate_long(new BigInteger(event.data, 10), 0));
      callback(m);
    };
    worker.postMessage({ n: this.n.toString(), e: this.e.toString(), d: this.d.toString(), pkcs1imified: pkcs1imified });
  },

  verify_ssh_sig : function(data, msg) {
    if (msg.get_string() != 'ssh-rsa') {
      return false;
    }
    var sig = paramikojs.util.inflate_long(msg.get_string(), true);
    // verify the signature by SHA'ing the data and encrypting it using the
    // public key.  some wackiness ensues where we "pkcs1imify" the 20-byte
    // hash into a string as long as the RSA key.
    var hash_obj = paramikojs.util.inflate_long(this._pkcs1imify(new kryptos.hash.SHA(data).digest()), true);
    var rsa = new kryptos.publicKey.RSA().construct(this.n, this.e);
    return rsa.verify(hash_obj, [sig]);
  },

  _encode_key : function() {
    if (!this.p || !this.q) {
      throw new paramikojs.ssh_exception.SSHException('Not enough key info to write private key file');
    }
    keylist = [ 0, this.n, this.e, this.d, this.p, this.q,
                this.d % (this.p - 1), this.d % (this.q - 1),
                paramikojs.util.mod_inverse(this.q, this.p) ];
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
    this._write_private_key_file('RSA', filename, this._encode_key(), password);
  },
    
  write_private_key : function(file_obj, password) {
    this._write_private_key('RSA', file_obj, this._encode_key(), password);
  },

  /*
    Generate a new private RSA key.  This factory function can be used to
    generate a new host key or authentication key.

    @param bits: number of bits the generated key should be.
    @type bits: int
    @param progress_func: an optional function to call at key points in
        key generation (used by C{pyCrypto.PublicKey}).
    @type progress_func: function
    @return: new private key
    @rtype: L{RSAKey}
  */
  generate : function(bits, progress_func) {
    var rsa = new kryptos.publicKey.RSA().generate(bits, paramikojs.rng.read, progress_func);
    var key = new paramikojs.RSAKey(null, null, null, null, [rsa.e, rsa.n], null);
    key.d = rsa.d;
    key.p = rsa.p;
    key.q = rsa.q;
    return key;
  },


  // internals...


  /*
    turn a 20-byte SHA1 hash into a blob of data as large as the key's N,
    using PKCS1's \"emsa-pkcs1-v1_5\" encoding.  totally bizarre.
  */
  _pkcs1imify : function(data) {
    var SHA1_DIGESTINFO = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14';
    var size = paramikojs.util.deflate_long(this.n, 0).length;
    var filler = new Array(size - SHA1_DIGESTINFO.length - data.length - 3 + 1).join('\xff');
    return '\x00\x01' + filler + '\x00' + SHA1_DIGESTINFO + data;
  },

  _from_private_key_file : function(filename, password) {
    var data;
    var keylist = null;
    try {
      data = this._read_private_key_file('RSA', filename, password);
    } catch (ex) {
      if (ex instanceof paramikojs.ssh_exception.IsPuttyKey) {
        data = null;
        keylist = this._read_putty_private_key('RSA', ex.lines, password);
      } else {
        throw ex;
      }
    }
    this._decode_key(data, keylist);
  },

  _from_private_key : function(file_obj, password) {
    var data = this._read_private_key('RSA', file_obj, password);
    this._decode_key(data);
  },

  _decode_key : function(data, keylist) {
    // private key file contains:
    // RSAPrivateKey = { version = 0, n, e, d, p, q, d mod p-1, d mod q-1, q**-1 mod p }
    try {
      keylist = keylist || new paramikojs.BER(data).decode();
    } catch(ex) {
      throw new paramikojs.ssh_exception.SSHException('Unable to parse key file');
    }
    if (!(keylist instanceof Array) || keylist.length < 4 || keylist[0] != 0) {
      throw new paramikojs.ssh_exception.SSHException('Not a valid RSA private key file (bad ber encoding)');
    }
    this.n = keylist[1];
    this.e = keylist[2];
    this.d = keylist[3];
    // not really needed
    this.p = keylist[4];
    this.q = keylist[5];
    this.size = paramikojs.util.bit_length(this.n);
  }
};
