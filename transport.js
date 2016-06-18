paramikojs.transport = function(observer) {
  this.observer = observer;

  this.rng = new kryptos.random.Random();
  this.packetizer = new paramikojs.Packetizer(this);
  this.packetizer.set_hexdump(false);
  this.local_version = 'SSH-' + this._PROTO_ID + '-' + this._CLIENT_ID + this.observer.version;
  this.remote_version = '';
  this.local_cipher = this.remote_cipher = '';
  this.local_kex_init = this.remote_kex_init = null;
  this.local_mac = this.remote_mac = null;
  this.local_compression = this.remote_compression = null;
  this.session_id = null;
  this.host_key_type = null;
  this.host_key = null;

  // state used during negotiation
  this.kex_engine = null;
  this.H = null;
  this.K = null;

  this.active = false;
  this.initial_kex_done = false;
  this.in_kex = false;
  this.authenticated = false;
  this._expected_packet = [];

  // tracking open channels
  this._channels = { };
  this.channel_events = { };       // (id -> Event)
  this.channels_seen = { };        // (id -> True)
  this._channel_counter = 1;
  this.max_packet_size = Math.pow(2, 15);
  this.window_size = 64 * this.max_packet_size;
  this._x11_handler = null;
  this._tcp_handler = null;

  this.saved_exception = null;
  this.clear_to_send = false;
  this.logger = paramikojs.util.get_logger();
  this.packetizer.set_log(this.logger);
  this.auth_handler = null;
  this.global_response = null;     // response Message from an arbitrary global request
  this.completion_event = null;    // user-defined event callbacks
  this.banner_timeout = 15;        // how long (seconds) to wait for the SSH banner
}

paramikojs.transport.prototype = {
  fullBuffer : '',
  gotWelcomeMessage : false,
  authenticatedCallback : null,
  writeCallback : null,

  toUTF8 : ((Components && Components.classes) ? Components.classes["@mozilla.org/intl/utf8converterservice;1"].getService(Components.interfaces.nsIUTF8ConverterService)
                       : { convertStringToUTF8: function(str) { return str; } }),
  fromUTF8 : ((Components && Components.classes) ? Components.classes["@mozilla.org/intl/scriptableunicodeconverter"].getService   (Components.interfaces.nsIScriptableUnicodeConverter)
                         : { ConvertFromUnicode: function(str) { return str; }, Finish: function() { /* do nothing */ } }),
 
  _PROTO_ID : '2.0',
  _CLIENT_ID : 'ParamikoJS_',

  // todo fixme aes128-ctr is preferred on paramiko, but too slow for JS right now.  for now, using blowfish
  // working on optimizing this...
  _preferred_ciphers : [ 'blowfish-cbc', 'aes128-ctr', 'aes256-ctr', 'aes128-cbc', 'aes256-cbc', '3des-cbc',
                         'arcfour128', 'arcfour256' ],
  _preferred_macs : [ 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1', 'hmac-md5', 'hmac-sha1-96', 'hmac-md5-96' ],
  _preferred_keys : [ 'ssh-rsa', 'ssh-dss' ],
  _preferred_kex  : [ 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group1-sha1' ],
  _preferred_compression : [ 'none' ],

  _cipher_info : {
    'aes128-ctr': { 'class': kryptos.cipher.AES, 'mode': kryptos.cipher.AES.MODE_CTR, 'block-size': 16, 'key-size': 16 },
    'aes256-ctr': { 'class': kryptos.cipher.AES, 'mode': kryptos.cipher.AES.MODE_CTR, 'block-size': 16, 'key-size': 32 },
    'blowfish-cbc': { 'class': kryptos.cipher.Blowfish, 'mode': kryptos.cipher.Blowfish.MODE_CBC, 'block-size': 8, 'key-size': 16 },
    'aes128-cbc': { 'class': kryptos.cipher.AES, 'mode': kryptos.cipher.AES.MODE_CBC, 'block-size': 16, 'key-size': 16 },
    'aes256-cbc': { 'class': kryptos.cipher.AES, 'mode': kryptos.cipher.AES.MODE_CBC, 'block-size': 16, 'key-size': 32 },
    '3des-cbc': { 'class': kryptos.cipher.DES3, 'mode': kryptos.cipher.DES3.MODE_CBC, 'block-size': 8, 'key-size': 24 },
    'arcfour128': { 'class': kryptos.cipher.ARC4, 'mode': null, 'block-size': 8, 'key-size': 16 },
    'arcfour256': { 'class': kryptos.cipher.ARC4, 'mode': null, 'block-size': 8, 'key-size': 32 }
  },

  _mac_info : {
    'hmac-sha1': { 'class': kryptos.hash.HMAC_SHA, 'size': 20, 'digest_size': kryptos.hash.SHA.digest_size },
    'hmac-sha1-96': { 'class': kryptos.hash.HMAC_SHA, 'size': 12, 'digest_size': kryptos.hash.SHA.digest_size },
    'hmac-sha2-256': { 'class': kryptos.hash.HMAC_SHA256, 'size': 32, 'digest_size': kryptos.hash.SHA256.digest_size },
    'hmac-sha2-512': { 'class': kryptos.hash.HMAC_SHA512, 'size': 64, 'digest_size': kryptos.hash.SHA512.digest_size },
    'hmac-md5': { 'class': kryptos.hash.HMAC_MD5, 'size': 16, 'digest_size': kryptos.hash.MD5.digest_size },
    'hmac-md5-96': { 'class': kryptos.hash.HMAC_MD5, 'size': 12, 'digest_size': kryptos.hash.MD5.digest_size }
  },

  _key_info : {
    'ssh-rsa': function(msg) { return new paramikojs.RSAKey(msg) },
    'ssh-dss': function(msg) { return new paramikojs.DSSKey(msg) }
  },

  _kex_info : {
    'diffie-hellman-group1-sha1': function(self) { return new paramikojs.KexGroup1(self) },
    'diffie-hellman-group14-sha1': function(self) { return new paramikojs.KexGroup14(self) },
    'diffie-hellman-group-exchange-sha1': function(self) { return new paramikojs.KexGex(self) },
    'diffie-hellman-group-exchange-sha256':  function(self) { return new paramikojs.KexGexSHA256(self) },
  },

  _compression_info : {
    // zlib@openssh.com is just zlib, but only turned on after a successful
    // authentication.  openssh servers may only offer this type because
    // they've had troubles with security holes in zlib in the past.
    'zlib@openssh.com': [ paramikojs.ZlibCompressor, paramikojs.ZlibDecompressor ],
    'zlib': [ paramikojs.ZlibCompressor, paramikojs.ZlibDecompressor ],
    'none': [ null, null ]
  },

  _modulus_pack : null,


  /*
    Negotiate a new SSH2 session as a client.  This is the first step after
    creating a new L{Transport}.  A separate thread is created for protocol
    negotiation.

    If an event is passed in, this method returns immediately.  When
    negotiation is done (successful or not), the given C{Event} will
    be triggered.  On failure, L{is_active} will return C{False}.

    (Since 1.4) If C{event} is C{None}, this method will not return until
    negotation is done.  On success, the method returns normally.
    Otherwise an SSHException is raised.

    After a successful negotiation, you will usually want to authenticate,
    calling L{auth_password <Transport.auth_password>} or
    L{auth_publickey <Transport.auth_publickey>}.

    @note: L{connect} is a simpler method for connecting as a client.

    @note: After calling this method (or L{start_server} or L{connect}),
        you should no longer directly read from or write to the original
        socket object.

    @param event: an event to trigger when negotiation is complete
        (optional)
    @type event: threading.Event

    @raise SSHException: if negotiation fails (and no C{event} was passed
        in)
  */
  start_client : function() {
    this.active = true;
  },

  /*
    Close this session, and any open channels that are tied to it.
  */
  close : function() {
    if (!this.active) {
      return;
    }
    this.active = false;
    for (var x = 0; x < this._channels.length; ++x) {
      this._channels[x]._unlink();
    }
    this.packetizer.close();
  },

  /*
    Return the host key of the server (in client mode).

    @raise SSHException: if no session is currently active.
  */
  get_remote_server_key : function() {
    if (!this.active || !this.initial_kex_done) {
      throw new paramikojs.ssh_exception.SSHException('No existing session');
    }

    return this.host_key;
  },

  /*
    Return true if this session is active (open).
  */
  is_active : function() {
    return this.active;
  },

  /*
    Request a new channel to the server, of type C{"session"}.  This
    is just an alias for C{open_channel('session')}.

    @return: a new L{Channel}
    @rtype: L{Channel}

    @raise SSHException: if the request is rejected or the session ends
        prematurely
  */
  open_session : function(on_success) {
    return this.open_channel('session', null, null, on_success);
  },

  /*
    Request a new channel to the client, of type C{"x11"}.  This
    is just an alias for C{open_channel('x11', src_addr=src_addr)}.

    @param src_addr: the source address of the x11 server (port is the
        x11 port, ie. 6010)
    @type src_addr: (str, int)
    @return: a new L{Channel}
    @rtype: L{Channel}

    @raise SSHException: if the request is rejected or the session ends
        prematurely
  */
  open_x11_channel : function(src_addr) {
    return this.open_channel('x11', null, src_addr);
  },

  /*
    Request a new channel back to the client, of type C{"forwarded-tcpip"}.
    This is used after a client has requested port forwarding, for sending
    incoming connections back to the client.

    @param src_addr: originator's address
    @param src_port: originator's port
    @param dest_addr: local (server) connected address
    @param dest_port: local (server) connected port
  */
  open_forwarded_tcpip_channel : function(src_addr, src_port, dest_addr, dest_port) {
    return this.open_channel('forwarded-tcpip', [dest_addr, dest_port], [src_addr, src_port]);
  },

  /*
    Request a new channel to the server.  L{Channel}s are socket-like
    objects used for the actual transfer of data across the session.
    You may only request a channel after negotiating encryption (using
    L{connect} or L{start_client}) and authenticating.

    @param kind: the kind of channel requested (usually C{"session"},
        C{"forwarded-tcpip"}, C{"direct-tcpip"}, or C{"x11"})
    @type kind: str
    @param dest_addr: the destination address of this port forwarding,
        if C{kind} is C{"forwarded-tcpip"} or C{"direct-tcpip"} (ignored
        for other channel types)
    @type dest_addr: (str, int)
    @param src_addr: the source address of this port forwarding, if
        C{kind} is C{"forwarded-tcpip"}, C{"direct-tcpip"}, or C{"x11"}
    @type src_addr: (str, int)
    @return: a new L{Channel} on success
    @rtype: L{Channel}

    @raise SSHException: if the request is rejected or the session ends
        prematurely
  */
  open_channel : function(kind, dest_addr, src_addr, on_success) {
    if (!this.active) {
      throw new paramikojs.ssh_exception.SSHException('SSH session not active');
    }

    var chanid = this._next_channel();
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_OPEN));
    m.add_string(kind);
    m.add_int(chanid);
    m.add_int(this.window_size);
    m.add_int(this.max_packet_size);
    if (kind == 'forwarded-tcpip' || kind == 'direct-tcpip') {
      m.add_string(dest_addr[0]);
      m.add_int(dest_addr[1]);
      m.add_string(src_addr[0]);
      m.add_int(src_addr[1]);
    } else if (kind == 'x11') {
      m.add_string(src_addr[0]);
      m.add_int(src_addr[1]);
    }
    var chan = new paramikojs.Channel(chanid);
    this._channels[chanid] = chan;
    this._channels[chanid].on_success = on_success;
    this.channels_seen[chanid] = true;
    chan._set_transport(this);
    chan._set_window(this.window_size, this.max_packet_size);

    this._send_user_message(m);

    return chan;
  },

  /*
    Ask the server to forward TCP connections from a listening port on
    the server, across this SSH session.

    If a handler is given, that handler is called from a different thread
    whenever a forwarded connection arrives.  The handler parameters are::

        handler(channel, (origin_addr, origin_port), (server_addr, server_port))

    where C{server_addr} and C{server_port} are the address and port that
    the server was listening on.

    If no handler is set, the default behavior is to send new incoming
    forwarded connections into the accept queue, to be picked up via
    L{accept}.

    @param address: the address to bind when forwarding
    @type address: str
    @param port: the port to forward, or 0 to ask the server to allocate
        any port
    @type port: int
    @param handler: optional handler for incoming forwarded connections
    @type handler: function(Channel, (str, int), (str, int))
    @return: the port # allocated by the server
    @rtype: int

    @raise SSHException: if the server refused the TCP forward request
  */
  request_port_forward : function(address, port, handler) {
    if (!this.active) {
      throw new paramikojs.ssh_exception.SSHException('SSH session not active');
    }
    var response = this.global_request('tcpip-forward', [address, port], true);
    if (!response) {
      throw new paramikojs.ssh_exception.SSHException('TCP forwarding request denied');
    }
    if (port == 0) {
      port = response.get_int();
    }
    if (!handler) {
      var self = this;
      function default_handler(channel, src_addr, dest_addr) {
        self._queue_incoming_channel(channel);
      }
      handler = default_handler;
    }
    this._tcp_handler = handler;
    return port;
  },

  /*
    Ask the server to cancel a previous port-forwarding request.  No more
    connections to the given address & port will be forwarded across this
    ssh connection.

    @param address: the address to stop forwarding
    @type address: str
    @param port: the port to stop forwarding
    @type port: int
  */
  cancel_port_forward : function(address, port) {
    if (!this.active) {
      return;
    }
    this._tcp_handler = null;
    this.global_request('cancel-tcpip-forward', [address, port], true);
  },

  /*
    Create an SFTP client channel from an open transport.  On success,
    an SFTP session will be opened with the remote host, and a new
    SFTPClient object will be returned.

    @return: a new L{SFTPClient} object, referring to an sftp session
        (channel) across this transport
    @rtype: L{SFTPClient}
  */
  open_sftp_client : function(callback) {
    paramikojs.SFTPClient.from_transport(this, callback);
  },

  /*
    Send a junk packet across the encrypted link.  This is sometimes used
    to add "noise" to a connection to confuse would-be attackers.  It can
    also be used as a keep-alive for long lived connections traversing
    firewalls.

    @param bytes: the number of random bytes to send in the payload of the
        ignored packet -- defaults to a random number from 10 to 41.
    @type bytes: int
  */
  send_ignore : function(bytes) {
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_IGNORE));
    if (!bytes) {
      bytes = (this.rng.read(1).charCodeAt(0) % 32) + 10;
    }
    m.add_bytes(this.rng.read(bytes));
    this._send_user_message(m);
  },

  /*
    Force this session to switch to new keys.  Normally this is done
    automatically after the session hits a certain number of packets or
    bytes sent or received, but this method gives you the option of forcing
    new keys whenever you want.  Negotiating new keys causes a pause in
    traffic both ways as the two sides swap keys and do computations.  This
    method returns when the session has switched to new keys.

    @raise SSHException: if the key renegotiation failed (which causes the
        session to end)
  */
  renegotiate_keys : function() {
    this._send_kex_init();
  },

  /*
    Turn on/off keepalive packets (default is off).  If this is set, after
    C{interval} seconds without sending any data over the connection, a
    "keepalive" packet will be sent (and ignored by the remote host).  This
    can be useful to keep connections alive over a NAT, for example.

    @param interval: seconds to wait before sending a keepalive packet (or
        0 to disable keepalives).
    @type interval: int
  */
  set_keepalive : function(interval) {
    var self = this;
    var callback = function() {
      self.global_request('keepalive@lag.net', null, false);
    };
    this.packetizer.set_keepalive(interval, callback);
  },

  /*
    Make a global request to the remote host.  These are normally
    extensions to the SSH2 protocol.

    @param kind: name of the request.
    @type kind: str
    @param data: an optional tuple containing additional data to attach
        to the request.
    @type data: tuple
    @param wait: C{True} if this method should not return until a response
        is received; C{False} otherwise.
    @type wait: bool
    @return: a L{Message} containing possible additional data if the
        request was successful (or an empty L{Message} if C{wait} was
        C{False}); C{None} if the request was denied.
    @rtype: L{Message}
  */
  global_request : function(kind, data, wait) {
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_GLOBAL_REQUEST));
    m.add_string(kind);
    m.add_boolean(wait);
    if (data) {
      m.add(data);
    }
    this._log(DEBUG, 'Sending global request: ' + kind);
    this._send_user_message(m);
    return this.global_response;
  },

  /*
    Negotiate an SSH2 session, and optionally verify the server's host key
    and authenticate using a password or private key.  This is a shortcut
    for L{start_client}, L{get_remote_server_key}, and
    L{Transport.auth_password} or L{Transport.auth_publickey}.  Use those
    methods if you want more control.

    You can use this method immediately after creating a Transport to
    negotiate encryption with a server.  If it fails, an exception will be
    thrown.  On success, the method will return cleanly, and an encrypted
    session exists.  You may immediately call L{open_channel} or
    L{open_session} to get a L{Channel} object, which is used for data
    transfer.

    @note: If you fail to supply a password or private key, this method may
    succeed, but a subsequent L{open_channel} or L{open_session} call may
    fail because you haven't authenticated yet.

    @param hostkey: the host key expected from the server, or C{None} if
        you don't want to do host key verification.
    @type hostkey: L{PKey<pkey.PKey>}
    @param username: the username to authenticate as.
    @type username: str
    @param password: a password to use for authentication, if you want to
        use password authentication; otherwise C{None}.
    @type password: str
    @param pkey: a private key to use for authentication, if you want to
        use private key authentication; otherwise C{None}.
    @type pkey: L{PKey<pkey.PKey>}

    @raise SSHException: if the SSH2 negotiation fails, the host key
        supplied by the server is incorrect, or authentication fails.
  */
  connect : function(hostkey, authenticatedCallback, username, password, pkey, auth_success) {
    if (hostkey) {
      this._preferred_keys = [ hostkey.get_name() ];
    }

    this.start_client();

    this.authenticatedCallback = authenticatedCallback || function() {
      // check host key if we were given one
      var key = this.get_remote_server_key();
      if (hostkey) {
        if ((key.get_name() != hostkey.get_name()) || (key.toString() != hostkey.toString())) {
          this._log(DEBUG, 'Bad host key from server');
          this._log(DEBUG, 'Expected: %s: %s' + hostkey.get_name() + ':' + hostkey.toString());
          this._log(DEBUG, 'Got     : %s: %s' + key.get_name() + ': ' + key.toString());
          throw new paramikojs.ssh_exception.SSHException('Bad host key from server');
        }
        this._log(DEBUG, 'Host key verified (' + hostkey.get_name() + ')');
      }

      if (pkey || password) {
        if (password) {
          this._log(DEBUG, 'Attempting password auth...');
          this.auth_password(username, password);
        } else {
          this._log(DEBUG, 'Attempting public-key auth...');
          this.auth_publickey(username, pkey);
        }
      }
    };

    this.auth_callback = function(success, nextOptions, triedKeyboard, triedPublicKey) {
      if (success) {
        auth_success();
      } else if (nextOptions) {
        if (!triedKeyboard && nextOptions.indexOf('keyboard-interactive') != -1) {
          var handler = function(title, instructions, fields) {
            if (fields.length > 1) {
              throw new paramikojs.ssh_exception.SSHException('Fallback authentication failed.');
            }
            if (fields.length == 0) {
              // for some reason, at least on os x, a 2nd request will
              // be made with zero fields requested.  maybe it's just
              // to try to fake out automated scripting of the exact
              // type we're doing here.  *shrug* :)
              return [];
            }
            return [ password ];
          };
          this.auth_interactive(username, handler);
        } else if (!triedPublicKey && pkey && nextOptions.indexOf('publickey') != -1) {
          this.auth_publickey(username, pkey);
        } else {
          throw new paramikojs.ssh_exception.AuthenticationException('Authentication failed');
        }
      } else {
        throw new paramikojs.ssh_exception.AuthenticationException('Authentication failed');
      }
    };
  },

  /*
    Return any exception that happened during the last server request.
    This can be used to fetch more specific error information after using
    calls like L{start_client}.  The exception (if any) is cleared after
    this call.

    @return: an exception, or C{None} if there is no stored exception.
    @rtype: Exception

    @since: 1.1
  */
  get_exception : function() {
    var e = this.saved_exception;
    this.saved_exception = null;
    return e;
  },

  /*
    Return true if this session is active and authenticated.

    @return: True if the session is still open and has been authenticated
        successfully; False if authentication failed and/or the session is
        closed.
    @rtype: bool
  */
  is_authenticated : function() {
    return this.active && this.auth_handler && this.auth_handler.is_authenticated();
  },

  /*
    Return the username this connection is authenticated for.  If the
    session is not authenticated (or authentication failed), this method
    returns C{None}.

    @return: username that was authenticated, or C{None}.
    @rtype: string
  */
  get_username : function() {
    if (!this.active || !this.auth_handler) {
      return null;
    }
    return this.auth_handler.get_username();
  },

  /*
    Try to authenticate to the server using no authentication at all.
    This will almost always fail.  It may be useful for determining the
    list of authentication types supported by the server, by catching the
    L{BadAuthenticationType} exception raised.

    @param username: the username to authenticate as
    @type username: string
    @return: list of auth types permissible for the next stage of
        authentication (normally empty)
    @rtype: list

    @raise BadAuthenticationType: if "none" authentication isn't allowed
        by the server for this user
    @raise SSHException: if the authentication failed due to a network
        error

    @since: 1.5
  */
  auth_none : function(username) {
    if (!this.active || !this.initial_kex_done) {
      throw new paramikojs.ssh_exception.SSHException('No existing session');
    }
    this.auth_handler = new paramikojs.AuthHandler(this);
    this.auth_handler.auth_none(username);
    return this.auth_handler.wait_for_response();
  },

  /*
    Authenticate to the server using a password.  The username and password
    are sent over an encrypted link.

    If an C{event} is passed in, this method will return immediately, and
    the event will be triggered once authentication succeeds or fails.  On
    success, L{is_authenticated} will return C{True}.  On failure, you may
    use L{get_exception} to get more detailed error information.

    Since 1.1, if no event is passed, this method will block until the
    authentication succeeds or fails.  On failure, an exception is raised.
    Otherwise, the method simply returns.

    Since 1.5, if no event is passed and C{fallback} is C{True} (the
    default), if the server doesn't support plain password authentication
    but does support so-called "keyboard-interactive" mode, an attempt
    will be made to authenticate using this interactive mode.  If it fails,
    the normal exception will be thrown as if the attempt had never been
    made.  This is useful for some recent Gentoo and Debian distributions,
    which turn off plain password authentication in a misguided belief
    that interactive authentication is "more secure".  (It's not.)

    If the server requires multi-step authentication (which is very rare),
    this method will return a list of auth types permissible for the next
    step.  Otherwise, in the normal case, an empty list is returned.

    @param username: the username to authenticate as
    @type username: str
    @param password: the password to authenticate with
    @type password: str or unicode
    @param event: an event to trigger when the authentication attempt is
        complete (whether it was successful or not)
    @type event: threading.Event
    @param fallback: C{True} if an attempt at an automated "interactive"
        password auth should be made if the server doesn't support normal
        password auth
    @type fallback: bool
    @return: list of auth types permissible for the next stage of
        authentication (normally empty)
    @rtype: list

    @raise BadAuthenticationType: if password authentication isn't
        allowed by the server for this user (and no event was passed in)
    @raise AuthenticationException: if the authentication failed (and no
        event was passed in)
    @raise SSHException: if there was a network error
  */
  auth_password : function(username, password, event, fallback) {
    if (!this.active || !this.initial_kex_done) {
      // we should never try to send the password unless we're on a secure link
      throw new paramikojs.ssh_exception.SSHException('No existing session');
    }
    this.auth_handler = new paramikojs.AuthHandler(this);
    this.auth_handler.auth_password(username, password);
    return this.auth_handler.wait_for_response();
  },

  /*
    Authenticate to the server using a private key.  The key is used to
    sign data from the server, so it must include the private part.

    If an C{event} is passed in, this method will return immediately, and
    the event will be triggered once authentication succeeds or fails.  On
    success, L{is_authenticated} will return C{True}.  On failure, you may
    use L{get_exception} to get more detailed error information.

    Since 1.1, if no event is passed, this method will block until the
    authentication succeeds or fails.  On failure, an exception is raised.
    Otherwise, the method simply returns.

    If the server requires multi-step authentication (which is very rare),
    this method will return a list of auth types permissible for the next
    step.  Otherwise, in the normal case, an empty list is returned.

    @param username: the username to authenticate as
    @type username: string
    @param key: the private key to authenticate with
    @type key: L{PKey <pkey.PKey>}
    @param event: an event to trigger when the authentication attempt is
        complete (whether it was successful or not)
    @type event: threading.Event
    @return: list of auth types permissible for the next stage of
        authentication (normally empty)
    @rtype: list

    @raise BadAuthenticationType: if public-key authentication isn't
        allowed by the server for this user (and no event was passed in)
    @raise AuthenticationException: if the authentication failed (and no
        event was passed in)
    @raise SSHException: if there was a network error
  */
  auth_publickey : function(username, key) {
    if (!this.active || !this.initial_kex_done) {
      // we should never try to send the password unless we're on a secure link
      throw new paramikojs.ssh_exception.SSHException('No existing session');
    }
    this.auth_handler = new paramikojs.AuthHandler(this);
    this.auth_handler.auth_publickey(username, key);
    return this.auth_handler.wait_for_response();
  },

  /*
    Authenticate to the server interactively.  A handler is used to answer
    arbitrary questions from the server.  On many servers, this is just a
    dumb wrapper around PAM.

    This method will block until the authentication succeeds or fails,
    peroidically calling the handler asynchronously to get answers to
    authentication questions.  The handler may be called more than once
    if the server continues to ask questions.

    The handler is expected to be a callable that will handle calls of the
    form: C{handler(title, instructions, prompt_list)}.  The C{title} is
    meant to be a dialog-window title, and the C{instructions} are user
    instructions (both are strings).  C{prompt_list} will be a list of
    prompts, each prompt being a tuple of C{(str, bool)}.  The string is
    the prompt and the boolean indicates whether the user text should be
    echoed.

    A sample call would thus be:
    C{handler('title', 'instructions', [('Password:', False)])}.

    The handler should return a list or tuple of answers to the server's
    questions.

    If the server requires multi-step authentication (which is very rare),
    this method will return a list of auth types permissible for the next
    step.  Otherwise, in the normal case, an empty list is returned.

    @param username: the username to authenticate as
    @type username: string
    @param handler: a handler for responding to server questions
    @type handler: callable
    @param submethods: a string list of desired submethods (optional)
    @type submethods: str
    @return: list of auth types permissible for the next stage of
        authentication (normally empty).
    @rtype: list

    @raise BadAuthenticationType: if public-key authentication isn't
        allowed by the server for this user
    @raise AuthenticationException: if the authentication failed
    @raise SSHException: if there was a network error

    @since: 1.5
  */
  auth_interactive : function(username, handler, submethods) {
    if (!this.active || !this.initial_kex_done) {
      // we should never try to send the password unless we're on a secure link
      throw new paramikojs.ssh_exception.SSHException('No existing session');
    }
    this.auth_handler = new paramikojs.AuthHandler(this);
    this.auth_handler.auth_interactive(username, handler, submethods);
    return this.auth_handler.wait_for_response();
  },

  /*
    Turn on/off compression.  This will only have an affect before starting
    the transport (ie before calling L{connect}, etc).  By default,
    compression is off since it negatively affects interactive sessions.

    @param compress: C{True} to ask the remote client/server to compress
        traffic; C{False} to refuse compression
    @type compress: bool

    @since: 1.5.2
  */
  use_compression : function(compress) {
    if (compress) {
      this._preferred_compression = [ 'zlib@openssh.com', 'zlib', 'none' ];
    } else {
      this._preferred_compression = [ 'none', ];
    }
  },


  //  internals...

  _log : function(level, msg) {
    this.logger.log(level, msg);
  },

  // used by KexGex to find primes for group exchange
  _get_modulus_pack : function() {
    return this._modulus_pack;
  },

  _next_channel : function() {
    var chanid = this._channel_counter;
    while (this._channels[chanid]) {
      this._channel_counter = (this._channel_counter + 1) & 0xffffff;
      chanid = this._channel_counter;
    }
    this._channel_counter = (this._channel_counter + 1) & 0xffffff;
    return chanid;
  },

  // used by a Channel to remove itself from the active channel list;
  _unlink_channel : function(chanid) {
    delete this._channels[chanid];
  },

  _send_message : function(data) {
    this.packetizer.send_message(data);
  },

  /*
    send a message, but block if we're in key negotiation.  this is used
    for user-initiated requests.
  */
  _send_user_message : function(data) {
    if (!this.clear_to_send) {
      var self = this;
      var wait_callback = function() {
        self._send_user_message(data);
      };
      setTimeout(wait_callback, 100);
      return;
    }
    this._send_message(data);
  },

  // used by a kex object to set the K (root key) and H (exchange hash)
  _set_K_H : function(k, h) {
    this.K = k;
    this.H = h;
    if (!this.session_id) {
      this.session_id = h;
    }
  },

  // used by a kex object to register the next packet type it expects to see
  _expect_packet : function(ptypes) {
    this._expected_packet = [ptypes];
  },

  _verify_key : function(host_key, sig) {
    var key = this._key_info[this.host_key_type](new paramikojs.Message(host_key));
    if (!key) {
      throw new paramikojs.ssh_exception.SSHException('Unknown host key type');
    }
    if (!key.verify_ssh_sig(this.H, new paramikojs.Message(sig))) {
      throw new paramikojs.ssh_exception.SSHException('Signature verification (' + this.host_key_type + ') failed.');
    }
    this.host_key = key;
  },

  // id is 'A' - 'F' for the various keys used by ssh
  _compute_key : function(id, nbytes) {
    var m = new paramikojs.Message();
    m.add_mpint(this.K);
    m.add_bytes(this.H);
    m.add_byte(id);
    m.add_bytes(this.session_id);
    var out, sofar, digest;
    var hash_algo = this.kex_engine.hash_algo;
    out = sofar = new hash_algo(m.toString()).digest();
    while (out.length < nbytes) {
      m = new paramikojs.Message();
      m.add_mpint(this.K);
      m.add_bytes(this.H);
      m.add_bytes(sofar);
      digest = new hash_algo(m.toString()).digest();
      out += digest;
      sofar += digest;
    }
    return out.substring(0, nbytes);
  },

  _get_cipher : function(name, key, iv) {
    if (!(name in this._cipher_info)) {
      throw new paramikojs.ssh_exception.SSHException('Unknown client cipher ' + name);
    }
    if (name in {'arcfour128': true, 'arcfour256': true}) {
      // arcfour cipher
      var cipher = new this._cipher_info[name]['class'](key);
      // as per RFC 4345, the first 1536 bytes of keystream
      // generated by the cipher MUST be discarded
      cipher.encrypt(new Array(1536 + 1).join(" "));
      return cipher;
    } else if (name.indexOf("-ctr") == name.length - 4) {
      // CTR modes, we need a counter
      var counter = new paramikojs.util.Counter(this._cipher_info[name]['block-size'] * 8, paramikojs.util.inflate_long(iv, true));
      return new this._cipher_info[name]['class'](key, this._cipher_info[name]['mode'], iv, counter);
    } else {
      return new this._cipher_info[name]['class'](key, this._cipher_info[name]['mode'], iv);
    }
  },

  _set_x11_handler : function(handler) {
    // only called if a channel has turned on x11 forwarding
    if (!handler) {
      // by default, use the same mechanism as accept()
      var self = this;
      var default_handler = function(channel, src_addr) {
        self._queue_incoming_channel(channel);
      }
      this._x11_handler = default_handler;
    } else {
      this._x11_handler = handler;
    }
  },

  run : function() {
    if (!this.active || (!this.gotWelcomeMessage && this.fullBuffer.indexOf('\n') == -1)) {
      return;
    }

    if (this.gotWelcomeMessage && this.packetizer.need_rekey() && !this.in_kex) {
      this._send_kex_init();
    }

    try {
      var msg = !this.gotWelcomeMessage ? "" : this.packetizer.read_message();
    } catch(ex) {
      if (ex instanceof paramikojs.ssh_exception.WaitException) {
        // not enough data yet to complete the packet, defer
        return;
      } else {
        throw ex;
      }
    }

    if (!this.gotWelcomeMessage) {
      this.gotWelcomeMessage = true;
      this._check_banner();
      this.packetizer.write_all(this.local_version + '\r\n');
      this._expect_packet(paramikojs.MSG_KEXINIT);
      this.nextCommand();
      return;
    } else if (msg.ptype == paramikojs.MSG_IGNORE) {
      this.nextCommand();
      return;
    } else if (msg.ptype == paramikojs.MSG_DISCONNECT) {
      this._parse_disconnect(msg.m);
      this.active = false;
      this.packetizer.close();
      return;
    } else if (msg.ptype == paramikojs.MSG_DEBUG) {
      this._parse_debug(msg.m);
      this.nextCommand();
      return;
    }

    if (this._expected_packet.length > 0) {
      if (this._expected_packet.indexOf(msg.ptype) == -1) {
        throw new paramikojs.ssh_exception.SSHException('Expecting packet from ' + this._expected_packet + ', got ' + msg.ptype);
      }
      this._expected_packet = [];
      if ((msg.ptype >= 30) && (msg.ptype <= 39)) {
        this.kex_engine.parse_next(msg.ptype, msg.m);
        this.nextCommand();
        return;
      }
    }

    if (msg.ptype in this._handler_table) {
      this._handler_table[msg.ptype](this, msg.m);
    } else if (msg.ptype in this._channel_handler_table) {
      var chanid = msg.m.get_int();
      var chan = this._channels[chanid];
      if (chan) {
        this._channel_handler_table[msg.ptype](chan, msg.m);
      } else if (chanid in this.channels_seen) {
        this._log(DEBUG, 'Ignoring message for dead channel ' + chanid);
      } else {
        this._log(ERROR, 'Channel request for unknown channel ' + chanid);
        this.active = false;
        this.packetizer.close();
      }
    } else if (this.auth_handler && msg.ptype in this.auth_handler._handler_table) {
      this.auth_handler._handler_table[msg.ptype](this.auth_handler, msg.m);
    } else {
      this._log(WARNING, 'Oops, unhandled type ' + msg.ptype);
      var nmsg = new paramikojs.Message();
      nmsg.add_byte(String.fromCharCode(paramikojs.MSG_UNIMPLEMENTED));
      nmsg.add_int(msg.m.seqno);
      this._send_message(nmsg);
    }

    this.nextCommand();
  },

  nextCommand : function() {
    if (this.fullBuffer) {    // leftover from previous packet
      this.run();
    }
  },


  //  protocol stages


  _negotiate_keys : function(m) {
    // throws SSHException on anything unusual
    this.clear_to_send = false;
    if (!this.local_kex_init) {
      // remote side wants to renegotiate
      this._send_kex_init();
    }
    this._parse_kex_init(m);
    this.kex_engine.start_kex();
  },

  _check_banner : function() {
    var buf = this.packetizer.readline();
    if (buf.substring(0, 4) != 'SSH-') {
      throw new paramikojs.ssh_exception.SSHException('Indecipherable protocol version "' + buf + '"');
    }
    // save this server version string for later
    this.remote_version = buf;
    // pull off any attached comment
    var comment = '';
    var i = buf.indexOf(' ');
    if (i >= 0) {
      comment = buf.substring(i + 1);
      buf = buf.substring(0, i);
    }
    // parse out version string and make sure it matches
    var segs = buf.split('-');
    if (segs.length < 3) {
      throw new paramikojs.ssh_exception.SSHException('Invalid SSH banner');
    }
    var version = segs[1];
    var client = segs[2];
    if (version != '1.99' && version != '2.0') {
      throw new paramikojs.ssh_exception.SSHException('Incompatible version (' + version + ' instead of 2.0)');
    }
    this._log(INFO, 'Connected (version ' + version + ', client ' + client + (comment ? + ', ' + comment : '') + ')', 'input', "info");
  },

  /*
    announce to the other side that we'd like to negotiate keys, and what
    kind of key negotiation we support.
  */
  _send_kex_init : function() {
    this.clear_to_send = false;
    this.in_kex = true;
    var available_server_keys = this._preferred_keys;

    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_KEXINIT));
    m.add_bytes(this.rng.read(16));
    m.add_list(this._preferred_kex);
    m.add_list(available_server_keys);
    m.add_list(this._preferred_ciphers);
    m.add_list(this._preferred_ciphers);
    m.add_list(this._preferred_macs);
    m.add_list(this._preferred_macs);
    m.add_list(this._preferred_compression);
    m.add_list(this._preferred_compression);
    m.add_string('');
    m.add_string('');
    m.add_boolean(false);
    m.add_int(0);
    // save a copy for later (needed to compute a hash)
    this.local_kex_init = m.toString();
    this._send_message(m);
  },

  _parse_kex_init : function(m) {
    var cookie = m.get_bytes(16);
    var kex_algo_list = m.get_list();
    var server_key_algo_list = m.get_list();
    var client_encrypt_algo_list = m.get_list();
    var server_encrypt_algo_list = m.get_list();
    var client_mac_algo_list = m.get_list();
    var server_mac_algo_list = m.get_list();
    var client_compress_algo_list = m.get_list();
    var server_compress_algo_list = m.get_list();
    var client_lang_list = m.get_list();
    var server_lang_list = m.get_list();
    var kex_follows = m.get_boolean();
    var unused = m.get_int();

    this._log(DEBUG, 'kex algos: ' + kex_algo_list +
              '\nserver key: ' + server_key_algo_list + 
              '\nclient encrypt: ' + client_encrypt_algo_list + 
              '\nserver encrypt: ' + server_encrypt_algo_list + 
              '\nclient mac: ' + client_mac_algo_list + 
              '\nserver mac: ' + server_mac_algo_list + 
              '\nclient compress: ' + client_compress_algo_list + 
              '\nserver compress: ' + server_compress_algo_list + 
              '\nclient lang: ' + client_lang_list + 
              '\nserver lang: ' + server_lang_list + 
              '\nkex follows? ' + kex_follows);

    function filter(server, client) {
      var a = [];
      for (var x = 0; x < client.length; ++x) {
        if (server.indexOf(client[x]) != -1) {
          a.push(client[x]);
        }
      }
      return a;
    }

    // as a server, we pick the first item in the client's list that we support.
    // as a client, we pick the first item in our list that the server supports.
    var agreed_kex = filter(kex_algo_list, this._preferred_kex);
    if (!agreed_kex.length) {
      throw new paramikojs.ssh_exception.SSHException('Incompatible ssh peer (no acceptable kex algorithm)');
    }
    this.kex_engine = this._kex_info[agreed_kex[0]](this);

    var agreed_keys = filter(server_key_algo_list, this._preferred_keys);
    if (!agreed_keys.length) {
      throw new paramikojs.ssh_exception.SSHException('Incompatible ssh peer (no acceptable host key)');
    }
    this.host_key_type = agreed_keys[0];

    var agreed_local_ciphers = filter(client_encrypt_algo_list, this._preferred_ciphers);
    var agreed_remote_ciphers = filter(server_encrypt_algo_list, this._preferred_ciphers);
    if (!agreed_local_ciphers.length || !agreed_remote_ciphers.length) {
      throw new paramikojs.ssh_exception.SSHException('Incompatible ssh server (no acceptable ciphers)');
    }
    this.local_cipher = agreed_local_ciphers[0];
    this.remote_cipher = agreed_remote_ciphers[0];
    this._log(DEBUG, 'Ciphers agreed: local=' + this.local_cipher + ', remote=' + this.remote_cipher);

    var agreed_local_macs = filter(client_mac_algo_list, this._preferred_macs);
    var agreed_remote_macs = filter(server_mac_algo_list, this._preferred_macs);
    if (!agreed_local_macs.length || !agreed_remote_macs.length) {
      throw new paramikojs.ssh_exception.SSHException('Incompatible ssh server (no acceptable macs)');
    }
    this.local_mac = agreed_local_macs[0];
    this.remote_mac = agreed_remote_macs[0];

    var agreed_local_compression = filter(client_compress_algo_list, this._preferred_compression);
    var agreed_remote_compression = filter(server_compress_algo_list, this._preferred_compression);
    if (!agreed_local_compression.length || !agreed_remote_compression.length) {
      throw new paramikojs.ssh_exception.SSHException('Incompatible ssh server (no acceptable compression) ' + agreed_local_compression + ' ' + agreed_remote_compression + ' ' + this._preferred_compression);
    }
    this.local_compression = agreed_local_compression[0];
    this.remote_compression = agreed_remote_compression[0];

    this._log(DEBUG, 'using kex: ' + agreed_kex[0]
      + '\nserver key type: ' + this.host_key_type
      + '\ncipher: local ' + this.local_cipher + ', remote ' + this.remote_cipher
      + '\nmac: local ' + this.local_mac + ', remote ' + this.remote_mac
      + '\ncompression: local ' + this.local_compression + ', remote ' + this.remote_compression);

    // save for computing hash later...
    // now wait!  openssh has a bug (and others might too) where there are
    // actually some extra bytes (one NUL byte in openssh's case) added to
    // the end of the packet but not parsed.  turns out we need to throw
    // away those bytes because they aren't part of the hash.
    this.remote_kex_init = String.fromCharCode(paramikojs.MSG_KEXINIT) + m.get_so_far();
  },

  // switch on newly negotiated encryption parameters for inbound traffic
  _activate_inbound : function() {
    var block_size = this._cipher_info[this.remote_cipher]['block-size'];
    var IV_in = this._compute_key('B', block_size);
    var key_in = this._compute_key('D', this._cipher_info[this.remote_cipher]['key-size']);
    var engine = this._get_cipher(this.remote_cipher, key_in, IV_in);
    var mac_size = this._mac_info[this.remote_mac]['size'];
    var mac_engine = this._mac_info[this.remote_mac]['class'];
    var mac_engine_digest_size = this._mac_info[this.remote_mac]['digest_size'];
    // initial mac keys are done in the hash's natural size (not the potentially truncated
    // transmission size)
    var mac_key = this._compute_key('F', mac_engine_digest_size);
    this.packetizer.set_inbound_cipher(engine, block_size, mac_engine, mac_size, mac_key);
    var compress_in = this._compression_info[this.remote_compression][1];
    if (compress_in && (this.remote_compression != 'zlib@openssh.com' || this.authenticated)) {
      this._log(DEBUG, 'Switching on inbound compression ...');
      this.packetizer.set_inbound_compressor(new compress_in());
    }
  },

  // switch on newly negotiated encryption parameters for outbound traffic
  _activate_outbound : function() {
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_NEWKEYS));
    this._send_message(m);
    var block_size = this._cipher_info[this.local_cipher]['block-size'];
    var IV_out = this._compute_key('A', block_size);
    var key_out = this._compute_key('C', this._cipher_info[this.local_cipher]['key-size']);
    var engine = this._get_cipher(this.local_cipher, key_out, IV_out);
    var mac_size = this._mac_info[this.local_mac]['size'];
    var mac_engine = this._mac_info[this.local_mac]['class'];
    var mac_engine_digest_size = this._mac_info[this.local_mac]['digest_size'];
    // initial mac keys are done in the hash's natural size (not the potentially truncated
    // transmission size)
    var mac_key = this._compute_key('E', mac_engine_digest_size);
    this.packetizer.set_outbound_cipher(engine, block_size, mac_engine, mac_size, mac_key);
    var compress_out = this._compression_info[this.local_compression][0];
    if (compress_out && (this.local_compression != 'zlib@openssh.com' || this.authenticated)) {
      this._log(DEBUG, 'Switching on outbound compression ...');
      this.packetizer.set_outbound_compressor(new compress_out());
    }
    if (!this.packetizer.need_rekey()) {
      this.in_kex = false;
    }
    // we always expect to receive NEWKEYS now
    this._expect_packet(paramikojs.MSG_NEWKEYS);
  },

  _auth_trigger : function() {
    this.authenticated = true;
    // delayed initiation of compression
    if (this.local_compression == 'zlib@openssh.com') {
      var compress_out = this._compression_info[this.local_compression][0];
      this._log(DEBUG, 'Switching on outbound compression ...');
      this.packetizer.set_outbound_compressor(new compress_out());
    }
    if (this.remote_compression == 'zlib@openssh.com') {
      var compress_in = this._compression_info[this.remote_compression][1];
      this._log(DEBUG, 'Switching on inbound compression ...');
      this.packetizer.set_inbound_compressor(new compress_in());
    }
  },

  _parse_newkeys : function(m) {
    this._log(DEBUG, 'Switch to new keys ...');
    this._activate_inbound();
    // can also free a bunch of stuff here
    this.local_kex_init = this.remote_kex_init = null;
    this.K = null
    this.kex_engine = null
    if (!this.initial_kex_done) {
      // this was the first key exchange
      this.initial_kex_done = true;
    }
    // it's now okay to send data again (if this was a re-key)
    if (!this.packetizer.need_rekey()) {
      this.in_kex = false;
    }

    this.clear_to_send = true;

    if (this.authenticatedCallback) {
      this.authenticatedCallback();
      this.authenticatedCallback = null;
    }
  },

  _parse_disconnect : function(m) {
    var code = m.get_int();
    var desc = m.get_string();
    this._log(INFO, 'Disconnect (code ' + code + '): ' + desc);
  },

  _parse_global_request : function(m) {
    var kind = m.get_string();
    this._log(DEBUG, 'Received global request ' + kind);
    var want_reply = m.get_boolean();
    var ok = false;
    this._log(DEBUG, 'Rejecting "' + kind + '" global request from server.');
    var extra = [];
    if (want_reply) {
      var msg = new paramikojs.Message();
      msg.add_byte(String.fromCharCode(paramikojs.MSG_REQUEST_FAILURE));
      this._send_message(msg);
    }
  },

  _parse_request_success : function(m) {
    this._log(DEBUG, 'Global request successful.');
    this.global_response = m;
  },

  _parse_request_failure : function(m) {
    this._log(DEBUG, 'Global request denied.');
    this.global_response = null;
  },

  _parse_channel_open_success : function(m) {
    var chanid = m.get_int();
    var server_chanid = m.get_int();
    var server_window_size = m.get_int();
    var server_max_packet_size = m.get_int();
    var chan = this._channels[chanid];
    if (!chan) {
      this._log(DEBUG, 'Success for unrequested channel! [??]');
      return;
    }
    chan._set_remote_channel(server_chanid, server_window_size, server_max_packet_size);
    this._log(INFO, 'Secsh channel ' + chanid + ' opened.');
    if (chan.on_success) {
      chan.on_success(chan);
    }
  },

  _parse_channel_open_failure : function(m) {
    var chanid = m.get_int();
    var reason = m.get_int();
    var reason_str = m.get_string();
    var lang = m.get_string();
    var reason_text = reason in paramikojs.CONNECTION_FAILED_CODE ? paramikojs.CONNECTION_FAILED_CODE[reason] : '(unknown code)';
    this._log(INFO, 'Secsh channel ' + chanid + ' open FAILED: ' + reason_str + ': ' + reason_text);

    this.saved_exception = new paramikojs.ssh_exception.ChannelException(reason, reason_text);
  },

  _parse_channel_open : function(m) {
    var kind = m.get_string();
    var chanid = m.get_int();
    var initial_window_size = m.get_int();
    var max_packet_size = m.get_int();
    var reject = false;
    var origin_addr, origin_port;
    var server_addr, server_port;
    var mychanid;
    if (kind == 'x11' && this._x11_handler) {
      origin_addr = m.get_string();
      origin_port = m.get_int();
      this._log(DEBUG, 'Incoming x11 connection from ' + origin_addr + ':' + origin_port);
      my_chanid = this._next_channel();
    } else if (kind == 'forwarded-tcpip' && this._tcp_handler) {
      server_addr = m.get_string();
      server_port = m.get_int();
      origin_addr = m.get_string();
      origin_port = m.get_int();
      this._log(DEBUG, 'Incoming tcp forwarded connection from ' + origin_addr + ':' + origin_port);
      my_chanid = this._next_channel();
    } else {
      this._log(DEBUG, 'Rejecting "' + kind + '" channel request from server.');
      reject = true;
      reason = paramikojs.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED;
    }

    if (reject) {
      var msg = new paramikojs.Message();
      msg.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_OPEN_FAILURE));
      msg.add_int(chanid);
      msg.add_int(reason);
      msg.add_string('');
      msg.add_string('en');
      this._send_message(msg);
      return;
    }

    var chan = new Channel(my_chanid);
    this._channels[my_chanid] = chan;
    this.channels_seen[my_chanid] = true;
    chan._set_transport(this);
    chan._set_window(this.window_size, this.max_packet_size);
    chan._set_remote_channel(chanid, initial_window_size, max_packet_size);

    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_OPEN_SUCCESS));
    m.add_int(chanid);
    m.add_int(my_chanid);
    m.add_int(this.window_size);
    m.add_int(this.max_packet_size);
    this._send_message(m);
    this._log(INFO, 'Secsh channel ' + my_chanid + ' (' + kind + ') opened.');
    if (kind == 'x11') {
      this._x11_handler(chan, [origin_addr, origin_port]);
    } else if (kind == 'forwarded-tcpip') {
      chan.origin_addr = [origin_addr, origin_port];
      this._tcp_handler(chan, [origin_addr, origin_port], [server_addr, server_port]);
    } else {
      this._queue_incoming_channel(chan);
    }
  },

  _parse_debug : function(m) {
    var always_display = m.get_boolean();
    var msg = m.get_string();
    var lang = m.get_string();
    this._log(DEBUG, 'Debug msg: ' + paramikojs.util.safe_string(msg));
  },

  _get_subsystem_handler : function(name) {
    if (name in this.subsystem_table) {
      return this.subsystem_table[name];
    }
    return [None, [], {}];
  },

  _handler_table : {
    21: function(self, m) { self._parse_newkeys(m) },
    80: function(self, m) { self._parse_global_request(m) },
    81: function(self, m) { self._parse_request_success(m) },
    82: function(self, m) { self._parse_request_failure(m) },
    91: function(self, m) { self._parse_channel_open_success(m) },
    92: function(self, m) { self._parse_channel_open_failure(m) },
    90: function(self, m) { self._parse_channel_open(m) },
    20: function(self, m) { self._negotiate_keys(m) }
  },

  _channel_handler_table : {
    99:  function(chan, m) { chan._request_success(m) },
    100: function(chan, m) { chan._request_failed(m) },
    94:  function(chan, m) { chan._feed(m) },
    95:  function(chan, m) { chan._feed_extended(m) },
    93:  function(chan, m) { chan._window_adjust(m) },
    98:  function(chan, m) { chan._handle_request(m) },
    96:  function(chan, m) { chan._handle_eof(m) },
    97:  function(chan, m) { chan._handle_close(m) }
  }
};
