/*
  Policy for automatically adding the hostname and new host key to the
  local L{HostKeys} object, and saving it.  This is used by L{SSHClient}.
*/
paramikojs.AutoAddPolicy = function () {
	
}

paramikojs.AutoAddPolicy.prototype = {
	missing_host_key : function(client, hostname, key, callback) {
    client._host_keys.add(hostname, key.get_name(), key);
    if (client._host_keys_filename) {
      client.save_host_keys(client._host_keys_filename);
    }
    debug('Adding ' + key.get_name() + ' host key for ' + hostname + ': ' + paramikojs.util.hexify(key.get_fingerprint()));

    callback(true);
  }
};

/*
  Policy for asking the user before adding the hostname and new host key to the
  local L{HostKeys} object, and saving it.  This is used by L{SSHClient}.
*/
paramikojs.AskPolicy = function () {
	
}

paramikojs.AskPolicy.prototype = {
	missing_host_key : function(client, hostname, key, callback) {
    var raw_fingerprint = paramikojs.util.hexify(key.get_fingerprint()).toLowerCase();
    var fingerprint = "";
    for (var x = 0; x < raw_fingerprint.length; x += 2) {
      fingerprint += raw_fingerprint[x] + raw_fingerprint[x + 1] + ':';
    }
    fingerprint = fingerprint.substring(0, fingerprint.length - 1);

    var cacheCallback = function(answer) {
      if (answer == 'y') {
        client._host_keys.add(hostname, key.get_name(), key);
        if (client._host_keys_filename) {
          client.save_host_keys(client._host_keys_filename);
        }
        debug('Adding ' + key.get_name() + ' host key for ' + hostname + ': ' + fingerprint);
        callback(true);
      } else if (!answer) {
        callback(false);
      } else {
        callback(true);
      }
    };

    client._observer.onSftpCache(null, key.get_name() + ' ' + key.get_bits() + '\n' + fingerprint, cacheCallback);
  }
};


/*
  Policy for automatically rejecting the unknown hostname & key.  This is
  used by L{SSHClient}.
*/
paramikojs.RejectPolicy = function () {
	
}

paramikojs.RejectPolicy.prototype = {
	missing_host_key : function(client, hostname, key, callback) {
    debug('Rejecting ' + key.get_name() + ' host key for ' + hostname + ': ' + paramikojs.util.hexify(key.get_fingerprint()));
    callback(false);
  }
};


/*
  Policy for logging a python-style warning for an unknown host key, but
  accepting it. This is used by L{SSHClient}.
*/
paramikojs.WarningPolicy = function () {
	
}

paramikojs.WarningPolicy.prototype = {
	missing_host_key : function(client, hostname, key, callback) {
    debug('Unknown ' + key.get_name() + ' host key for ' + hostname + ': ' + paramikojs.util.hexify(key.get_fingerprint()));
    callback(true);
  }
};


/*
  A high-level representation of a session with an SSH server.  This class
  wraps L{Transport}, L{Channel}, and L{SFTPClient} to take care of most
  aspects of authenticating and opening channels.  A typical use case is::

      client = SSHClient()
      client.load_system_host_keys()
      client.connect('ssh.example.com')
      stdin, stdout, stderr = client.exec_command('ls -l')

  You may pass in explicit overrides for authentication and server host key
  checking.  The default mechanism is to try to use local key files or an
  SSH agent (if one is running).

  @since: 1.6
*/
paramikojs.SSHClient = function () {
  /*
    Create a new SSHClient.
  */
  this._system_host_keys = new paramikojs.HostKeys();
  this._host_keys = new paramikojs.HostKeys();
  this._host_keys_filename = null;
  this._log_channel = null;
  this._policy = new paramikojs.RejectPolicy();
  this._transport = null;
  this._agent = null;

  this._observer = null;
}

paramikojs.SSHClient.prototype = {
	SSH_PORT : 22,

  /*
    Load host keys from a system (read-only) file.  Host keys read with
    this method will not be saved back by L{save_host_keys}.

    This method can be called multiple times.  Each new set of host keys
    will be merged with the existing set (new replacing old if there are
    conflicts).

    If C{filename} is left as C{None}, an attempt will be made to read
    keys from the user's local "known hosts" file, as used by OpenSSH,
    and no exception will be raised if the file can't be read.  This is
    probably only useful on posix.

    @param filename: the filename to read, or C{None}
    @type filename: str

    @raise IOError: if a filename was provided and the file could not be
        read
  */
  load_system_host_keys : function(filename) {
    if (!filename) {
      // try the user's .ssh key file, and mask exceptions
      this._system_host_keys.load('~/.ssh/known_hosts');
      return;
    }
    this._system_host_keys.load(filename);
  },

  /*
    Load host keys from a local host-key file.  Host keys read with this
    method will be checked I{after} keys loaded via L{load_system_host_keys},
    but will be saved back by L{save_host_keys} (so they can be modified).
    The missing host key policy L{AutoAddPolicy} adds keys to this set and
    saves them, when connecting to a previously-unknown server.

    This method can be called multiple times.  Each new set of host keys
    will be merged with the existing set (new replacing old if there are
    conflicts).  When automatically saving, the last hostname is used.

    @param filename: the filename to read
    @type filename: str

    @raise IOError: if the filename could not be read
  */
  load_host_keys : function(filename) {
    this._host_keys_filename = filename;
    this._host_keys.load(filename);
  },

  /*
    Save the host keys back to a file.  Only the host keys loaded with
    L{load_host_keys} (plus any added directly) will be saved -- not any
    host keys loaded with L{load_system_host_keys}.

    @param filename: the filename to save to
    @type filename: str

    @raise IOError: if the file could not be written
  */
  save_host_keys : function(filename) {
    this._host_keys.save(filename);
  },

  /*
    Get the local L{HostKeys} object.  This can be used to examine the
    local host keys or change them.

    @return: the local host keys
    @rtype: L{HostKeys}
  */
  get_host_keys : function() {
    return this._host_keys;
  },

  /*
    Set the policy to use when connecting to a server that doesn't have a
    host key in either the system or local L{HostKeys} objects.  The
    default policy is to reject all unknown servers (using L{RejectPolicy}).
    You may substitute L{AutoAddPolicy} or write your own policy class.

    @param policy: the policy to use when receiving a host key from a
        previously-unknown server
    @type policy: L{MissingHostKeyPolicy}
  */
  set_missing_host_key_policy : function(policy) {
    this._policy = policy;
  },

  /*
    Connect to an SSH server and authenticate to it.  The server's host key
    is checked against the system host keys (see L{load_system_host_keys})
    and any local host keys (L{load_host_keys}).  If the server's hostname
    is not found in either set of host keys, the missing host key policy
    is used (see L{set_missing_host_key_policy}).  The default policy is
    to reject the key and raise an L{SSHException}.

    Authentication is attempted in the following order of priority:

        - The C{pkey} or C{key_filename} passed in (if any)
        - Any key we can find through an SSH agent
        - Any "id_rsa" or "id_dsa" key discoverable in C{~/.ssh/}
        - Plain username/password auth, if a password was given

    If a private key requires a password to unlock it, and a password is
    passed in, that password will be used to attempt to unlock the key.

    @param hostname: the server to connect to
    @type hostname: str
    @param port: the server port to connect to
    @type port: int
    @param username: the username to authenticate as (defaults to the
        current local username)
    @type username: str
    @param password: a password to use for authentication or for unlocking
        a private key
    @type password: str
    @param pkey: an optional private key to use for authentication
    @type pkey: L{PKey}
    @param key_filename: the filename, or list of filenames, of optional
        private key(s) to try for authentication
    @type key_filename: str or list(str)
    @param timeout: an optional timeout (in seconds) for the TCP connect
    @type timeout: float
    @param allow_agent: set to False to disable connecting to the SSH agent
    @type allow_agent: bool
    @param look_for_keys: set to False to disable searching for discoverable
        private key files in C{~/.ssh/}
    @type look_for_keys: bool
    @param compress: set to True to turn on compression
    @type compress: bool

    @raise BadHostKeyException: if the server's host key could not be
        verified
    @raise AuthenticationException: if authentication failed
    @raise SSHException: if there was any other error connecting or
        establishing an SSH session
    @raise socket.error: if a socket error occurred while connecting
  */
  connect : function(observer, writeCallback, auth_success,
            hostname, port, username, password, pkey,
            key_filename, timeout, allow_agent, look_for_keys,
            compress) {
    port = port || this.SSH_PORT;
    allow_agent = allow_agent == undefined ? true : allow_agent;
    look_for_keys = look_for_keys == undefined ? true : look_for_keys;

    var self = this;
    var authenticatedCallback = function() { 
      var server_key = self._transport.get_remote_server_key();
      var keytype = server_key.get_name();
      var server_hostkey_name, our_server_key;

      if (port == self.SSH_PORT) {
        server_hostkey_name = hostname;
      } else {
        server_hostkey_name = "[" + hostname + "]:" + port;
      }
      if (self._system_host_keys._entries.length) {
        our_server_key = self._system_host_keys.get(server_hostkey_name)[keytype];
      }
      if (!our_server_key && self._host_keys._entries.length) {
        our_server_key = self._host_keys.get(server_hostkey_name)[keytype];
      }

      var cacheCallback = function(accepted) {
        if (!accepted) {
          self.close(true);
          return;
        }

        var key_filenames;
        if (!key_filename) {
          key_filenames = [];
        } else if (typeof key_filename == "string") {
          key_filenames = [ key_filename ];
        } else {
          key_filenames = key_filename;
        }
        self._auth(username, password, pkey, key_filenames, allow_agent, look_for_keys);
      };

      if (!our_server_key) {
        // will raise exception if the key is rejected; let that fall out
        self._policy.missing_host_key(self, server_hostkey_name, server_key, cacheCallback);
        // if the callback returns, assume the key is ok
        our_server_key = server_key;
      } else if (!server_key.compare(our_server_key)) {
        self._policy.missing_host_key(self, server_hostkey_name, server_key, cacheCallback);
        // if the callback returns, assume the key is ok
      } else {
        cacheCallback(true);
      }
    };

    this._observer = observer;
    this._transport = new paramikojs.transport(observer);
    this._transport.writeCallback = writeCallback;
    this._transport.use_compression(compress);
    this._transport.connect(null, authenticatedCallback, username, password, pkey, auth_success);

    return this._transport;
  },

  /*
    Close this SSHClient and its underlying L{Transport}.
  */
  close : function(legitClose) {
    if (!this._transport) {
      return;
    }
    this.legitClose = legitClose;
    this._transport.close();
    this._transport = null;

    if (this._agent) {
      this._agent.close();
      this._agent = null;
    }
  },

  /*
    Execute a command on the SSH server.  A new L{Channel} is opened and
    the requested command is executed.  The command's input and output
    streams are returned as python C{file}-like objects representing
    stdin, stdout, and stderr.

    @param command: the command to execute
    @type command: str
    @param bufsize: interpreted the same way as by the built-in C{file()} function in python
    @type bufsize: int
    @return: the stdin, stdout, and stderr of the executing command
    @rtype: tuple(L{ChannelFile}, L{ChannelFile}, L{ChannelFile})

    @raise SSHException: if the server fails to execute the command
  */
  exec_command : function(command, bufsize) {
    bufsize = bufsize || -1;
    var on_success = function() {
      chan.exec_command(command);
      var stdin = chan.makefile('wb', bufsize);
      var stdout = chan.makefile('rb', bufsize);
      var stderr = chan.makefile_stderr('rb', bufsize);
      return [stdin, stdout, stderr];
    };
    var chan = this._transport.open_session(on_success);
  },

  /*
    Start an interactive shell session on the SSH server.  A new L{Channel}
    is opened and connected to a pseudo-terminal using the requested
    terminal type and size.

    @param term: the terminal type to emulate (for example, C{"vt100"})
    @type term: str
    @param width: the width (in characters) of the terminal window
    @type width: int
    @param height: the height (in characters) of the terminal window
    @type height: int
    @return: a new channel connected to the remote shell
    @rtype: L{Channel}

    @raise SSHException: if the server fails to invoke a shell
  */
  invoke_shell : function(term, width, height, callback) {
    term = term || 'vt100';
    width = width || 80;
    height = height || 24;
    var on_success = function(chan) {
      chan.get_pty(term, width, height);
      chan.invoke_shell();
      callback(chan);
    };
    this._transport.open_session(on_success);
  },

  /*
    Open an SFTP session on the SSH server.

    @return: a new SFTP session object
    @rtype: L{SFTPClient}
  */
  open_sftp : function(callback) {
    this._transport.open_sftp_client(callback);
  },

  /*
    Return the underlying L{Transport} object for this SSH connection.
    This can be used to perform lower-level tasks, like opening specific
    kinds of channels.

    @return: the Transport for this connection
    @rtype: L{Transport}
  */
  get_transport : function() {
    return this._transport;
  },

  /*
    Try, in order:

        - The key passed in, if one was passed in.
        - Any key we can find through an SSH agent (if allowed).
        - Any "id_rsa" or "id_dsa" key discoverable in ~/.ssh/ (if allowed).
        - Plain username/password auth, if a password was given.

    (The password might be needed to unlock a private key.)
  */
  _auth : function(username, password, pkey, key_filenames, allow_agent, look_for_keys) {
    var saved_exception = null;
    var key;

    if (pkey) {
      try {
        this._log(DEBUG, 'Trying SSH key ' + paramikojs.util.hexify(pkey.get_fingerprint()));
        this._transport.auth_publickey(username, pkey);
        return;
      } catch (ex) {
        saved_exception = ex;
      }
    }

    for (var y = 0; y < key_filenames.length; ++y) {
      for (var x = 0; x < 2; ++x) {
        try {
          var pkey_class = [paramikojs.RSAKey, paramikojs.DSSKey][x];
          key = new pkey_class(null, null, key_filenames[y], password);
          this._log(DEBUG, 'Trying key ' + paramikojs.util.hexify(key.get_fingerprint()) + ' from ' + key_filenames[y]);
          this._transport.auth_publickey(username, key);
          return;
        } catch(ex) {
          this._log(DEBUG, 'Tried key: ' + ex.message);
          saved_exception = ex;
        }
      }
    }

    if (false && allow_agent) { // todo fixme, agent sockets don't work right now...
      if (!this._agent) {
        this._agent = new paramikojs.Agent();
      }

      for (key in this._agent.get_keys()) {
        try {
          this._log(DEBUG, 'Trying SSH agent key ' + paramikojs.util.hexify(key.get_fingerprint()));
          this._transport.auth_publickey(username, key);
          return;
        } catch(ex) {
          saved_exception = ex;
        }
      }
    }

    var keyfiles = [];
    var rsa_key = localFile.init('~/.ssh/id_rsa');
    var dsa_key = localFile.init('~/.ssh/id_dsa');
    if (rsa_key && rsa_key.exists()) {
      keyfiles.push([paramikojs.RSAKey, rsa_key]);
    }
    if (dsa_key && dsa_key.exists()) {
      keyfiles.push([paramikojs.DSSKey, dsa_key]);
    }

    if (!look_for_keys) {
      keyfiles = [];
    }

    for (var x = 0; x < keyfiles.length; ++x) {
      try {
        key = new keyfiles[x][0](null, null, keyfiles[x][1].path, password);
        this._log(DEBUG, 'Trying discovered key ' + paramikojs.util.hexify(key.get_fingerprint()) + ' in ' + keyfiles[x][1].path);
        this._transport.auth_publickey(username, key);
        return;
      } catch(ex) {
        saved_exception = ex;
      }
    }

    if (password) {
      try {
        this._transport.auth_password(username, password);
        return;
      } catch(ex) {
        saved_exception = ex;
      }
    }

    // if we got an auth-failed exception earlier, re-raise it
    if (saved_exception) {
      throw saved_exception;
    }
    throw new paramikojs.ssh_exception.AuthenticationException('No authentication methods available');
  },

  _log : function(level, msg) {
    this._transport._log(level, msg);
  }
};
