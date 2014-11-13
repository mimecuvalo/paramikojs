/*
  Representation of a line in an OpenSSH-style "known hosts" file.
*/
paramikojs.HostKeyEntry = function(hostnames, key) {
  this.valid = hostnames && key;
  this.hostnames = hostnames;
  this.key = key;
}

paramikojs.HostKeyEntry.prototype = {
  /*
    Parses the given line of text to find the names for the host,
    the type of key, and the key data. The line is expected to be in the
    format used by the openssh known_hosts file.

    Lines are expected to not have leading or trailing whitespace.
    We don't bother to check for comments or empty lines.  All of
    that should be taken care of before sending the line to us.

    @param line: a line from an OpenSSH known_hosts file
    @type line: str
  */
  from_line : function(line) {
    var fields = line.split(' ');
    if (fields.length < 3) {
      // Bad number of fields
      return null;
    }
    fields = fields.slice(0, 3);

    var names = fields[0];
    var keytype = fields[1];
    var key = fields[2];
    names = names.split(',');

    // Decide what kind of key we're looking at and create an object
    // to hold it accordingly.
    if (keytype == 'ssh-rsa') {
      key = new paramikojs.RSAKey(null, base64.decodestring(key));
    } else if (keytype == 'ssh-dss') {
      key = new paramikojs.DSSKey(null, base64.decodestring(key));
    } else {
      key = new paramikojs.UnknownKey(keytype, base64.decodestring(key));
    }

    return new paramikojs.HostKeyEntry(names, key);
  },

  /*
    Returns a string in OpenSSH known_hosts file format, or None if
    the object is not in a valid state.  A trailing newline is
    included.
  */
  to_line : function() {
    if (this.valid) {
      return this.hostnames.join(',') + ' ' + this.key.get_name() + ' ' + this.key.get_base64() + '\n';
    }
    return null;
  }
};


/*
  Representation of an openssh-style "known hosts" file.  Host keys can be
  read from one or more files, and then individual hosts can be looked up to
  verify server keys during SSH negotiation.

  A HostKeys object can be treated like a dict; any dict lookup is equivalent
  to calling L{lookup}.

  @since: 1.5.3
*/
paramikojs.HostKeys = function(filename) {
  /*
    Create a new HostKeys object, optionally loading keys from an openssh
    style host-key file.

    @param filename: filename to load host keys from, or C{None}
    @type filename: str
  */
  // emulate a dict of { hostname: { keytype: PKey } }
  this._entries = [];
  if (filename) {
    this.load(filename);
  }
}

paramikojs.HostKeys.prototype = {
  /*
    Add a host key entry to the table.  Any existing entry for a
    C{(hostname, keytype)} pair will be replaced.

    @param hostname: the hostname (or IP) to add
    @type hostname: str
    @param keytype: key type (C{"ssh-rsa"} or C{"ssh-dss"})
    @type keytype: str
    @param key: the key to add
    @type key: L{PKey}
  */
  add : function(hostname, keytype, key) {
    for (var x = 0; x < this._entries.length; ++x) {
      if (this._entries[x].hostnames.indexOf(hostname) != -1 && this._entries[x].key.get_name() == keytype) {
        this._entries[x].key = key;
        return;
      }
    }
    this._entries.push(new paramikojs.HostKeyEntry([hostname], key));
  },

  /*
    Read a file of known SSH host keys, in the format used by openssh.
    This type of file unfortunately doesn't exist on Windows, but on
    posix, it will usually be stored in
    C{os.path.expanduser("~/.ssh/known_hosts")}.

    If this method is called multiple times, the host keys are merged,
    not cleared.  So multiple calls to C{load} will just call L{add},
    replacing any existing entries and adding new ones.

    @param filename: name of the file to read host keys from
    @type filename: str

    @raise IOError: if there was an error reading the file
  */
  load : function(filename) {
    if ((Components && Components.classes)) { // Mozilla
      var file = localFile.init(filename);
      if (!file.exists()) {
        this._entries = [];
        return;
      }

      var fstream = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance(Components.interfaces.nsIFileInputStream);
      fstream.init(file, -1, 0, 0);

      var charset = "UTF-8";
      var is = Components.classes["@mozilla.org/intl/converter-input-stream;1"].createInstance(Components.interfaces.nsIConverterInputStream);
      is.init(fstream, charset, 1024, 0xFFFD);
      is.QueryInterface(Components.interfaces.nsIUnicharLineInputStream);
      this.loadHelper(is);
    } else {  // Chrome
      var self = this;
      chrome.storage.local.get("host_keys", function(value) {
        is = value.host_keys || '';
        self.loadHelper(is);
      });
    }
  },

  loadHelper : function(is) {
    var line = {};
    var cont;
    do {
      line = {};
      if ((Components && Components.classes)) { // Mozilla
        cont = is.readLine(line);
        line = line.value.trim();
      } else {  // Chrome
        line = is.substring(0, is.indexOf('\n'));
        is = is.substring(line.length + 1);
        line = line.trim();
        cont = line.length;
      }
      if (!line.length || line[0] == '#') {
        continue;
      }
      var e = new paramikojs.HostKeyEntry().from_line(line);
      if (e) {
        this._entries.push(e);
      }
      // Now you can do something with line.value
    } while (cont);

    if ((Components && Components.classes)) {
      is.close();
    }
  },

  /*
    Save host keys into a file, in the format used by openssh.  The order of
    keys in the file will be preserved when possible (if these keys were
    loaded from a file originally).  The single exception is that combined
    lines will be split into individual key lines, which is arguably a bug.

    @param filename: name of the file to write
    @type filename: str

    @raise IOError: if there was an error writing the file

    @since: 1.6.1
  */
  save : function(filename) {
    if ((Components && Components.classes)) { // Mozilla
      var file = localFile.init(filename);
      var foStream = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance(Components.interfaces.nsIFileOutputStream);
      foStream.init(file, 0x02 | 0x08 | 0x20, 0644, 0);
      var converter = Components.classes["@mozilla.org/intl/converter-output-stream;1"].createInstance(Components.interfaces.nsIConverterOutputStream);
      converter.init(foStream, "UTF-8", 0, 0);
    }

    var data = "";
    for (var x = 0; x < this._entries.length; ++x) {
      var line = this._entries[x].to_line();
      if (line) {
        data += line;
      }
    }

    if ((Components && Components.classes)) { // Mozilla
      converter.writeString(data);
      converter.close();
    } else {
      chrome.storage.local.set({'host_keys': data});
    }
  },

  /*
    Find a hostkey entry for a given hostname or IP.  If no entry is found,
    C{None} is returned.  Otherwise a dictionary of keytype to key is
    returned.  The keytype will be either C{"ssh-rsa"} or C{"ssh-dss"}.

    @param hostname: the hostname (or IP) to lookup
    @type hostname: str
    @return: keys associated with this host (or C{None})
    @rtype: dict(str, L{PKey})
  */
  lookup : function(hostname) {
    var entries = {};
    for (var x = 0; x < this._entries.length; ++x) {
      for (var y = 0; y < this._entries[x].hostnames.length; ++y) {
        var h = this._entries[x].hostnames[y];
        if ((h.indexOf('|1|') == 0 && this.hash_host(hostname, h) == h) || h == hostname) {
          entries[this._entries[x].key.get_name()] = this._entries[x].key;
        }
      }
    }
    return entries;
  },

  get : function(hostname) {
    return this.lookup(hostname);
  },

  /*
    Return True if the given key is associated with the given hostname
    in this dictionary.

    @param hostname: hostname (or IP) of the SSH server
    @type hostname: str
    @param key: the key to check
    @type key: L{PKey}
    @return: C{True} if the key is associated with the hostname; C{False}
        if not
    @rtype: bool
  */
  check : function(hostname, key) {
    var k = this.lookup(hostname);
    if (!k) {
      return false;
    }
    var host_key = k.get(key.get_name(), null);
    if (!host_key) {
      return false;
    }
    return host_key.toString() == key.toString();
  },

  /*
    Remove all host keys from the dictionary.
  */
  clear : function() {
    this._entries = [];
  },

  keys : function() {
    var ret = [];
    for (var x = 0; x < this._entries.length; ++x) {
      for (var y = 0; y < this._entries[x].hostnames.length; ++y) {
        var h = this._entries[x].hostnames[y];
        if (ret.indexOf(h) == -1) {
          ret.push(h);
        }
      }
    }
    return ret;
  },

  values : function() {
    var ret = [];
    var keys = this.keys();
    for (var x; x < keys.length; ++x) {
      ret.push(this.lookup(keys[x]));
    }
    return ret;
  },

  /*
    Return a "hashed" form of the hostname, as used by openssh when storing
    hashed hostnames in the known_hosts file.

    @param hostname: the hostname to hash
    @type hostname: str
    @param salt: optional salt to use when hashing (must be 20 bytes long)
    @type salt: str
    @return: the hashed hostname
    @rtype: str
  */
  hash_host : function(hostname, salt) {
    if (!salt) {
      salt = paramikojs.rng.read(kryptos.hash.SHA.digest_size);
    } else {
      if (salt.indexOf('|1|') == 0) {
        salt = salt.split('|')[2];
      }
      salt = base64.decodestring(salt);
    }
    var hmac = kryptos.hash.HMAC(salt, hostname, kryptos.hash.HMAC_SHA);
    var hostkey = '|1|' + base64.encodestring(salt) + '|' + base64.encodestring(hmac);
    return hostkey.replace('\n', '');
  }
};
