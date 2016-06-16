/*
  Base class for public keys.
*/

paramikojs.PKey = function(msg, data) {
/*
  Create a new instance of this public key type.  If C{msg} is given,
  the key's public part(s) will be filled in from the message.  If
  C{data} is given, the key's public part(s) will be filled in from
  the string.

  @param msg: an optional SSH L{Message} containing a public key of this
  type.
  @type msg: L{Message}
  @param data: an optional string containing a public key of this type
  @type data: str

  @raise SSHException: if a key cannot be created from the C{data} or
  C{msg} given, or no key was passed in.
*/
}

paramikojs.PKey.prototype = {
  // known encryption types for private key files:
  _CIPHER_TABLE : {
    'AES-128-CBC': { 'cipher': kryptos.cipher.AES, 'keysize': 16, 'blocksize': 16, 'mode': kryptos.cipher.AES.MODE_CBC },
    'DES-EDE3-CBC': { 'cipher': kryptos.cipher.DES3, 'keysize': 24, 'blocksize': 8, 'mode': kryptos.cipher.DES3.MODE_CBC }
  },

  /*
    Return a string of an SSH L{Message} made up of the public part(s) of
    this key.  This string is suitable for passing to L{__init__} to
    re-create the key object later.

    @return: string representation of an SSH key message.
    @rtype: str
  */
  toString : function() {
    return '';
  },

  /*
    Return the name of this private key implementation.

    @return: name of this private key type, in SSH terminology (for
    example, C{"ssh-rsa"}).
    @rtype: str
  */
  get_name : function() {
    return '';
  },

  /*
    Return the number of significant bits in this key.  This is useful
    for judging the relative security of a key.

    @return: bits in the key.
    @rtype: int
  */
  get_bits : function(self) {
    return 0;
  },

  /*
    Return C{True} if this key has the private part necessary for signing
    data.

    @return: C{True} if this is a private key.
    @rtype: bool
  */
  can_sign : function() {
    return false;
  },

  /*
    Return an MD5 fingerprint of the public part of this key.  Nothing
    secret is revealed.

    @return: a 16-byte string (binary) of the MD5 fingerprint, in SSH
        format.
    @rtype: str
  */
  get_fingerprint : function() {
    return new kryptos.hash.MD5(this.toString()).digest();
  },

  /*
    Return a base64 string containing the public part of this key.  Nothing
    secret is revealed.  This format is compatible with that used to store
    public key files or recognized host keys.

    @return: a base64 string containing the public part of the key.
    @rtype: str
  */
  get_base64 : function() {
    return base64.encodestring(this.toString()).replace('\n', '');
  },

  /*
    Sign a blob of data with this private key, and return a L{Message}
    representing an SSH signature message.

    @param rng: a secure random number generator.
    @type rng: L{Crypto.Util.rng.RandomPool}
    @param data: the data to sign.
    @type data: str
    @return: an SSH signature message.  # mime: changed to callback instead of return to use Worker's
    @rtype: L{Message}
  */
  sign_ssh_data : function(rng, data, callback) {
    callback('');
  },

  /*
    Given a blob of data, and an SSH message representing a signature of
    that data, verify that it was signed with this key.

    @param data: the data that was signed.
    @type data: str
    @param msg: an SSH signature message
    @type msg: L{Message}
    @return: C{True} if the signature verifies correctly; C{False}
        otherwise.
    @rtype: boolean
  */
  verify_ssh_sig : function(data, msg) {
    return false;
  },

  /*
    Create a key object by reading a private key file.  If the private
    key is encrypted and C{password} is not C{None}, the given password
    will be used to decrypt the key (otherwise L{PasswordRequiredException}
    is thrown).  Through the magic of python, this factory method will
    exist in all subclasses of PKey (such as L{RSAKey} or L{DSSKey}), but
    is useless on the abstract PKey class.

    @param filename: name of the file to read
    @type filename: str
    @param password: an optional password to use to decrypt the key file,
        if it's encrypted
    @type password: str
    @return: a new key object based on the given private key
    @rtype: L{PKey}

    @raise IOError: if there was an error reading the file
    @raise PasswordRequiredException: if the private key file is
        encrypted, and C{password} is C{None}
    @raise SSHException: if the key file is invalid
  */
  from_private_key_file : function(filename, password) {
    var key = new this(null, null, filename, password);
    return key;
  },

  /*
    Create a key object by reading a private key from a file (or file-like)
    object.  If the private key is encrypted and C{password} is not C{None},
    the given password will be used to decrypt the key (otherwise
    L{PasswordRequiredException} is thrown).
    
    @param file_obj: the file to read from
    @type file_obj: file
    @param password: an optional password to use to decrypt the key, if it's
        encrypted
    @type password: str
    @return: a new key object based on the given private key
    @rtype: L{PKey}
    
    @raise IOError: if there was an error reading the key
    @raise PasswordRequiredException: if the private key file is encrypted,
        and C{password} is C{None}
    @raise SSHException: if the key file is invalid
  */
  from_private_key : function(file_obj, password) {
    var key = new this(null, null, null, password, null, file_obj);
    return key;
  },

  /*
    Write private key contents into a file.  If the password is not
    C{None}, the key is encrypted before writing.

    @param filename: name of the file to write
    @type filename: str
    @param password: an optional password to use to encrypt the key file
    @type password: str

    @raise IOError: if there was an error writing the file
    @raise SSHException: if the key is invalid
  */
  write_private_key_file : function(filename, password) {
    throw 'Not implemented in PKey';
  },

  /*
    Write private key contents into a file (or file-like) object.  If the
    password is not C{None}, the key is encrypted before writing.
    
    @param file_obj: the file object to write into
    @type file_obj: file
    @param password: an optional password to use to encrypt the key
    @type password: str
    
    @raise IOError: if there was an error writing to the file
    @raise SSHException: if the key is invalid
  */
  write_private_key : function(file_obj, password) {
    throw 'Not implemented in PKey';
  },

  /*
    Read an SSH2-format private key file, looking for a string of the type
    C{"BEGIN xxx PRIVATE KEY"} for some C{xxx}, base64-decode the text we
    find, and return it as a string.  If the private key is encrypted and
    C{password} is not C{None}, the given password will be used to decrypt
    the key (otherwise L{PasswordRequiredException} is thrown).

    @param tag: C{"RSA"} or C{"DSA"}, the tag used to mark the data block.
    @type tag: str
    @param filename: name of the file to read.
    @type filename: str
    @param password: an optional password to use to decrypt the key file,
        if it's encrypted.
    @type password: str
    @return: data blob that makes up the private key.
    @rtype: str

    @raise IOError: if there was an error reading the file.
    @raise PasswordRequiredException: if the private key file is
        encrypted, and C{password} is C{None}.
    @raise SSHException: if the key file is invalid.
  */
  _read_private_key_file : function(tag, filename, password) {
    var file = !Components ? filename : localFile.init(filename);
    var data = this._read_private_key(tag, file, password);
    return data;
  },

  _read_private_key : function(tag, f, password) {
    var lines;
    if (!(Components && Components.classes)) {  // Chrome
      lines = gKeys[f];
    } else {
      lines = "";
      var fstream = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance(Components.interfaces.nsIFileInputStream);
      var cstream = Components.classes["@mozilla.org/intl/converter-input-stream;1"].createInstance(Components.interfaces.nsIConverterInputStream);
      fstream.init(f, -1, 0, 0);
      cstream.init(fstream, "UTF-8", 0, 0); // you can use another encoding here if you wish

      var read = 0;
      do {
        var str = {};
        read = cstream.readString(0xffffffff, str); // read as much as we can and put it in str.value
        lines += str.value;
      } while (read != 0);
      cstream.close(); // this closes fstream
    }

    lines = lines.indexOf('\r\n') != -1 ? lines.split('\r\n') : lines.split('\n');

    if (lines.length && lines[0].indexOf("PuTTY-User-Key-File-") == 0) {
      throw new paramikojs.ssh_exception.IsPuttyKey("puttykey", lines);
    }

    var start = 0;
    while (start < lines.length && (lines[start].trim() != '-----BEGIN ' + tag + ' PRIVATE KEY-----')) {
      start += 1;
    }
    if (start >= lines.length) {
      throw new paramikojs.ssh_exception.SSHException('not a valid ' + tag + ' private key file');
    }
    // parse any headers first
    var headers = {};
    start += 1;
    while (start < lines.length) {
      var l = lines[start].split(': ');
      if (l.length == 1) {
        break;
      }
      headers[l[0].toLowerCase()] = l[1].trim();
      start += 1;
    }
    // find end
    var end = start;
    while ((lines[end].trim() != '-----END ' + tag + ' PRIVATE KEY-----') && end < lines.length) {
      end += 1;
    }
    // if we trudged to the end of the file, just try to cope.
    var data;
    try {
      data = base64.decodestring(lines.slice(start, end).join(''));
    } catch (ex) {
      throw new paramikojs.ssh_exception.SSHException('base64 decoding error: ' + ex.toString());
    }
    // if password was passed in, but unencrypted
    if (!('proc-type' in headers) && password) {   // mime: don't return if we are trying with a password though
      throw new paramikojs.ssh_exception.SSHException('Private key file is not encrypted but password used.');
    }
    if (!('proc-type' in headers)) {
      // unencrypted: done
      return data;
    }
    // encrypted keyfile: will need a password
    if (headers['proc-type'] != '4,ENCRYPTED') {
      throw new paramikojs.ssh_exception.SSHException('Unknown private key structure "' + headers['proc-type'] + '"');
    }
    var h = headers['dek-info'].split(',');
    var encryption_type = h[0];
    var saltstr = h[1];
    if (!(encryption_type in this._CIPHER_TABLE)) {
      throw new paramikojs.ssh_exception.SSHException('Unknown private key cipher "' + encryption_type + '"');
    }
    // if no password was passed in, raise an exception pointing out that we need one
    if (!password) {
      throw new paramikojs.ssh_exception.PasswordRequiredException('Private key file is encrypted');
    }
    var cipher = this._CIPHER_TABLE[encryption_type]['cipher'];
    var keysize = this._CIPHER_TABLE[encryption_type]['keysize'];
    var mode = this._CIPHER_TABLE[encryption_type]['mode'];
    var salt = paramikojs.util.unhexify(saltstr);
    var key = paramikojs.util.generate_key_bytes(kryptos.hash.MD5, salt, password, keysize);
    return new cipher(key, mode, salt).decrypt(data);
  },

  /**
   * Interprets PuTTY's ".ppk" file.
   *
   * <h2>Notes</h2>
   * <ol>
   * <li>
   * The file appears to be a text file but it doesn't have the fixed encoding.
   * So we just use the platform default encoding, which is what PuTTY seems to use.
   * Fortunately, the important part is all ASCII, so this shouldn't really hurt
   * the interpretation of the key.
   * </ol>
   *
   * <h2>Sample PuTTY file format</h2>
   * <pre>
  PuTTY-User-Key-File-2: ssh-rsa
  Encryption: none
  Comment: rsa-key-20080514
  Public-Lines: 4
  AAAAB3NzaC1yc2EAAAABJQAAAIEAiPVUpONjGeVrwgRPOqy3Ym6kF/f8bltnmjA2
  BMdAtaOpiD8A2ooqtLS5zWYuc0xkW0ogoKvORN+RF4JI+uNUlkxWxnzJM9JLpnvA
  HrMoVFaQ0cgDMIHtE1Ob1cGAhlNInPCRnGNJpBNcJ/OJye3yt7WqHP4SPCCLb6nL
  nmBUrLM=
  Private-Lines: 8
  AAAAgGtYgJzpktzyFjBIkSAmgeVdozVhgKmF6WsDMUID9HKwtU8cn83h6h7ug8qA
  hUWcvVxO201/vViTjWVz9ALph3uMnpJiuQaaNYIGztGJBRsBwmQW9738pUXcsUXZ
  79KJP01oHn6Wkrgk26DIOsz04QOBI6C8RumBO4+F1WdfueM9AAAAQQDmA4hcK8Bx
  nVtEpcF310mKD3nsbJqARdw5NV9kCxPnEsmy7Sy1L4Ob/nTIrynbc3MA9HQVJkUz
  7V0va5Pjm/T7AAAAQQCYbnG0UEekwk0LG1Hkxh1OrKMxCw2KWMN8ac3L0LVBg/Tk
  8EnB2oT45GGeJaw7KzdoOMFZz0iXLsVLNUjNn2mpAAAAQQCN6SEfWqiNzyc/w5n/
  lFVDHExfVUJp0wXv+kzZzylnw4fs00lC3k4PZDSsb+jYCMesnfJjhDgkUA0XPyo8
  Emdk
  Private-MAC: 50c45751d18d74c00fca395deb7b7695e3ed6f77
   * </pre>
   *
   * @author Kohsuke Kawaguchi
   */
  _read_putty_private_key : function(tag, lines, passphrase) {
    var headers = {};
    var payload = {};

    var headerName = null;

    for (var x = 0; x < lines.length; ++x) {
      var line = lines[x];

      var idx = line.indexOf(": ");
      if (idx > 0) {
        headerName = line.substring(0, idx);
        headers[headerName] = line.substring(idx + 2);
      } else {
        var s = payload[headerName];
        if (!s) {
          s = line;
        } else {
          s += line;
        }

        payload[headerName] = s;
      }
    }

    tag = tag == "DSA" ? "DSS" : tag;
    if (headers["PuTTY-User-Key-File-2"].substring(4).toUpperCase() != tag) {
      throw new paramikojs.ssh_exception.SSHException('not a valid ' + tag + ' private key file');
    }

    var encrypted = headers["Encryption"] == "aes256-cbc";
    var publicKey = base64.decodestring(payload["Public-Lines"]);
    var privateLines = base64.decodestring(payload["Private-Lines"]);


    /**
     * Converts a passphrase into a key, by following the convention that PuTTY uses.
     *
     * <p>
     * This is used to decrypt the private key when it's encrypted.
     */
    var toKey = function(passphrase) {
      var digest = new kryptos.hash.SHA();

      digest.update("\0\0\0\0");
      digest.update(passphrase);
      var key1 = digest.digest();

      digest = new kryptos.hash.SHA();
      digest.update("\0\0\0\1");
      digest.update(passphrase);
      var key2 = digest.digest();

      return (key1 + key2).substring(0, 32);
    };

    if (encrypted) {
      var key = toKey(passphrase);

      var aes = new kryptos.cipher.AES(key, kryptos.cipher.AES.MODE_CBC, new Array(16 + 1).join('\0'));

      privateLines = aes.decrypt(privateLines);
    }

    // check MAC
    if (headers["Private-MAC"]) {
      var key = new kryptos.hash.SHA("putty-private-key-file-mac-key");
      if (encrypted) {
        key.update(passphrase);
      }
      key = key.digest();

      var message = new paramikojs.Message();
      message.add_string(headers["PuTTY-User-Key-File-2"]);
      message.add_string(headers["Encryption"]);
      message.add_string(headers["Comment"]);
      message.add_string(publicKey);
      message.add_string(privateLines);

      var realmac = binascii.hexlify(kryptos.hash.HMAC(key, message.toString(), kryptos.hash.HMAC_SHA));

      if (headers["Private-MAC"] != realmac) {
        throw new paramikojs.ssh_exception.SSHException('Unable to parse key file');
      }
    }

    var privateKey = privateLines;

    var keylist = [];
    if (headers["PuTTY-User-Key-File-2"] == "ssh-rsa") {
      var m = new paramikojs.Message(publicKey);
      m.get_string();              // skip this
      keylist.push(0);
      var e = m.get_mpint();       // e comes first in putty's format instead of n
      keylist.push(m.get_mpint()); // n
      keylist.push(e);

      m = new paramikojs.Message(privateKey);
      keylist.push(m.get_mpint()); // d
      keylist.push(m.get_mpint()); // p
      keylist.push(m.get_mpint()); // q
    } else {
      var m = new paramikojs.Message(publicKey);
      m.get_string();              // skip this
      keylist.push(0);
      keylist.push(m.get_mpint()); // p
      keylist.push(m.get_mpint()); // q
      keylist.push(m.get_mpint()); // g
      keylist.push(m.get_mpint()); // y

      m = new paramikojs.Message(privateKey);
      keylist.push(m.get_mpint()); // x
    }

    return keylist;
  },

  /*
    Write an SSH2-format private key file in a form that can be read by
    paramiko or openssh.  If no password is given, the key is written in
    a trivially-encoded format (base64) which is completely insecure.  If
    a password is given, DES-EDE3-CBC is used.

    @param tag: C{"RSA"} or C{"DSA"}, the tag used to mark the data block.
    @type tag: str
    @param filename: name of the file to write.
    @type filename: str
    @param data: data blob that makes up the private key.
    @type data: str
    @param password: an optional password to use to encrypt the file.
    @type password: str

    @raise IOError: if there was an error writing the file.
  */
  _write_private_key_file : function(tag, filename, data, password) {
    var file = localFile.init(filename);
    this._write_private_key(tag, f, data, password);
  },

  _write_private_key : function(tag, f, data, password) {
    if(!(Components && Components.classes)) {
      throw new Error("Unable to write files without Mozilla's Components.classes"); //FIXME
    }
    
    var foStream = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance(Components.interfaces.nsIFileOutputStream);  
    foStream.init(f, 0x02 | 0x08 | 0x20, 0600, 0);  
    var converter = Components.classes["@mozilla.org/intl/converter-output-stream;1"].createInstance(Components.interfaces.nsIConverterOutputStream);  
    converter.init(foStream, "UTF-8", 0, 0);

    converter.writeString('-----BEGIN ' + tag + ' PRIVATE KEY-----\n');
    if (password) {
      // since we only support one cipher here, use it
      var cipher_name = this._CIPHER_TABLE.keys()[0];
      var cipher = this._CIPHER_TABLE[cipher_name]['cipher'];
      var keysize = this._CIPHER_TABLE[cipher_name]['keysize'];
      var blocksize = this._CIPHER_TABLE[cipher_name]['blocksize'];
      var mode = this._CIPHER_TABLE[cipher_name]['mode'];
      var salt = paramikojs.rng.read(blocksize);
      var key = paramikojs.util.generate_key_bytes(kryptos.hash.MD5, salt, password, keysize);
      if (data.length % blocksize != 0) {
        var n = blocksize - data.length % blocksize;
        //data += rng.read(n)
        //that would make more sense ^, but it confuses openssh.
        data += new Array(n + 1).join('\0');
      }
      data = new cipher(key, mode, salt).encrypt(data);
      converter.writeString('Proc-Type: 4,ENCRYPTED\n');
      converter.writeString('DEK-Info: ' + cipher_name + ',' + paramikojs.util.hexify(salt).toUpperCase() + '\n');
      converter.writeString('\n');
    }
    var s = base64.encodestring(data);
    // re-wrap to 64-char lines
    s = s.split('\n').join('');
    var t = "";
    for (var i = 0; i < s.length; i += 64) {
      t += s.substring(i, i+64) + '\n';
    }
    converter.writeString(t);
    converter.writeString('\n');
    converter.writeString('-----END ' + tag + ' PRIVATE KEY-----\n');

    converter.close(); // this closes foStream
  }
};
