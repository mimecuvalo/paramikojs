/*
  A secure tunnel across an SSH L{Transport}.  A Channel is meant to behave
  like a socket, and has an API that should be indistinguishable from the
  python socket API.

  Because SSH2 has a windowing kind of flow control, if you stop reading data
  from a Channel and its buffer fills up, the server will be unable to send
  you any more data until you read some of it.  (This won't affect other
  channels on the same transport -- all channels on a single transport are
  flow-controlled independently.)  Similarly, if the server isn't reading
  data you send, calls to L{send} may block, unless you set a timeout.  This
  is exactly like a normal network socket, so it shouldn't be too surprising.
*/
paramikojs.Channel = function (chanid) {
  /*
    Create a new channel.  The channel is not associated with any
    particular session or L{Transport} until the Transport attaches it.
    Normally you would only call this method from the constructor of a
    subclass of L{Channel}.

    @param chanid: the ID of this channel, as passed by an existing
        L{Transport}.
    @type chanid: int
  */

  this.chanid = chanid;
  this.remote_chanid = 0;
  this.transport = null;
  this.active = false;
  this.eof_received = 0;
  this.eof_sent = 0;
  this.in_buffer = "";
  this.in_stderr_buffer = "";
  this.timeout = null;
  this.closed = false;
  this.ultra_debug = false;
  this.in_window_size = 0;
  this.out_window_size = 0;
  this.in_max_packet_size = 0;
  this.out_max_packet_size = 0;
  this.in_window_threshold = 0;
  this.in_window_sofar = 0;
  this._name = chanid.toString();
  this.logger = paramikojs.util.get_logger();
  this._pipe = null;
  this.event_ready = false;
  this.combine_stderr = false;
  this.exit_status = -1;
  this.origin_addr = null;
}

// lower bound on the max packet size we'll accept from the remote host
paramikojs.Channel.MIN_PACKET_SIZE = 1024;

paramikojs.Channel.prototype = {
  /*
    Request a pseudo-terminal from the server.  This is usually used right
    after creating a client channel, to ask the server to provide some
    basic terminal semantics for a shell invoked with L{invoke_shell}.
    It isn't necessary (or desirable) to call this method if you're going
    to exectue a single command with L{exec_command}.

    @param term: the terminal type to emulate (for example, C{'vt100'})
    @type term: str
    @param width: width (in characters) of the terminal screen
    @type width: int
    @param height: height (in characters) of the terminal screen
    @type height: int
    
    @raise SSHException: if the request was rejected or the channel was
        closed
  */
  get_pty : function(term, width, height) {
    if (this.closed || this.eof_received || this.eof_sent || !this.active) {
      throw new paramikojs.ssh_exception.SSHException('Channel is not open');
    }
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_REQUEST));
    m.add_int(this.remote_chanid);
    m.add_string('pty-req');
    m.add_boolean(true);
    m.add_string(term || 'vt100');
    m.add_int(width || 80);
    m.add_int(height || 24);
    // pixel height, width (usually useless)
    m.add_int(0).add_int(0);
    m.add_string('');
    this.transport._send_user_message(m);
  },

  /*
    Request an interactive shell session on this channel.  If the server
    allows it, the channel will then be directly connected to the stdin,
    stdout, and stderr of the shell.
    
    Normally you would call L{get_pty} before this, in which case the
    shell will operate through the pty, and the channel will be connected
    to the stdin and stdout of the pty.
    
    When the shell exits, the channel will be closed and can't be reused.
    You must open a new channel if you wish to open another shell.
    
    @raise SSHException: if the request was rejected or the channel was
        closed
  */
  invoke_shell : function() {
    if (this.closed || this.eof_received || this.eof_sent || !this.active) {
      throw new paramikojs.ssh_exception.SSHException('Channel is not open');
    }
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_REQUEST));
    m.add_int(this.remote_chanid);
    m.add_string('shell');
    m.add_boolean(1);
    this.transport._send_user_message(m);
  },

  /*
    Execute a command on the server.  If the server allows it, the channel
    will then be directly connected to the stdin, stdout, and stderr of
    the command being executed.
    
    When the command finishes executing, the channel will be closed and
    can't be reused.  You must open a new channel if you wish to execute
    another command.

    @param command: a shell command to execute.
    @type command: str

    @raise SSHException: if the request was rejected or the channel was
        closed
  */
  exec_command : function(command) {
    if (this.closed || this.eof_received || this.eof_sent || !this.active) {
      throw new paramikojs.ssh_exception.SSHException('Channel is not open');
    }
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_REQUEST));
    m.add_int(this.remote_chanid);
    m.add_string('exec');
    m.add_boolean(true);
    m.add_string(command);
    this.transport._send_user_message(m);
  },

  /*
    Request a subsystem on the server (for example, C{sftp}).  If the
    server allows it, the channel will then be directly connected to the
    requested subsystem.
    
    When the subsystem finishes, the channel will be closed and can't be
    reused.

    @param subsystem: name of the subsystem being requested.
    @type subsystem: str

    @raise SSHException: if the request was rejected or the channel was
        closed
  */
  invoke_subsystem : function(subsystem) {
    if (this.closed || this.eof_received || this.eof_sent || !this.active) {
      throw new paramikojs.ssh_exception.SSHException('Channel is not open');
    }
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_REQUEST));
    m.add_int(this.remote_chanid);
    m.add_string('subsystem');
    m.add_boolean(true);
    m.add_string(subsystem);
    this.transport._send_user_message(m);
  },

  /*
    Resize the pseudo-terminal.  This can be used to change the width and
    height of the terminal emulation created in a previous L{get_pty} call.

    @param width: new width (in characters) of the terminal screen
    @type width: int
    @param height: new height (in characters) of the terminal screen
    @type height: int

    @raise SSHException: if the request was rejected or the channel was
        closed
  */
  resize_pty : function(width, height) {
    if (this.closed || this.eof_received || this.eof_sent || !this.active){
      throw new paramikojs.ssh_exception.SSHException('Channel is not open');
    }
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_REQUEST));
    m.add_int(this.remote_chanid);
    m.add_string('window-change');
    m.add_boolean(true);
    m.add_int(width || 80);
    m.add_int(height || 24);
    m.add_int(0).add_int(0);
    this.transport._send_user_message(m);
  },

  /*
    Return true if the remote process has exited and returned an exit
    status. You may use this to poll the process status if you don't
    want to block in L{recv_exit_status}. Note that the server may not
    return an exit status in some cases (like bad servers).
    
    @return: True if L{recv_exit_status} will return immediately
    @rtype: bool
    @since: 1.7.3
  */
  exit_status_ready : function() {
    return this.closed;
  },

  /*
    Return the exit status from the process on the server.  This is
    mostly useful for retrieving the results of an L{exec_command}.
    If the command hasn't finished yet, this method will wait until
    it does, or until the channel is closed.  If no exit status is
    provided by the server, -1 is returned.
    
    @return: the exit code of the process on the server.
    @rtype: int
    
    @since: 1.2
  */
  recv_exit_status : function() {
    return this.exit_status;
  },

  /*
    Send the exit status of an executed command to the client.  (This
    really only makes sense in server mode.)  Many clients expect to
    get some sort of status code back from an executed command after
    it completes.
    
    @param status: the exit code of the process
    @type status: int
    
    @since: 1.2
  */
  send_exit_status : function(status) {
    // in many cases, the channel will not still be open here.
    // that's fine.
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_REQUEST));
    m.add_int(this.remote_chanid);
    m.add_string('exit-status');
    m.add_boolean(false);
    m.add_int(status);
    this.transport._send_user_message(m);
  },

  /*
    Request an x11 session on this channel.  If the server allows it,
    further x11 requests can be made from the server to the client,
    when an x11 application is run in a shell session.
    
    From RFC4254::

        It is RECOMMENDED that the 'x11 authentication cookie' that is
        sent be a fake, random cookie, and that the cookie be checked and
        replaced by the real cookie when a connection request is received.
    
    If you omit the auth_cookie, a new secure random 128-bit value will be
    generated, used, and returned.  You will need to use this value to
    verify incoming x11 requests and replace them with the actual local
    x11 cookie (which requires some knoweldge of the x11 protocol).
    
    If a handler is passed in, the handler is called from another thread
    whenever a new x11 connection arrives.  The default handler queues up
    incoming x11 connections, which may be retrieved using
    L{Transport.accept}.  The handler's calling signature is::
    
        handler(channel: Channel, (address: str, port: int))
    
    @param screen_number: the x11 screen number (0, 10, etc)
    @type screen_number: int
    @param auth_protocol: the name of the X11 authentication method used;
        if none is given, C{"MIT-MAGIC-COOKIE-1"} is used
    @type auth_protocol: str
    @param auth_cookie: hexadecimal string containing the x11 auth cookie;
        if none is given, a secure random 128-bit value is generated
    @type auth_cookie: str
    @param single_connection: if True, only a single x11 connection will be
        forwarded (by default, any number of x11 connections can arrive
        over this session)
    @type single_connection: bool
    @param handler: an optional handler to use for incoming X11 connections
    @type handler: function
    @return: the auth_cookie used
  */
  request_x11 : function(screen_number, auth_protocol, auth_cookie, single_connection, handler) {
    if (this.closed || this.eof_received || this.eof_sent || !this.active) {
      throw new paramikojs.ssh_exception.SSHException('Channel is not open');
    }
    if (!auth_protocol) {
      auth_protocol = 'MIT-MAGIC-COOKIE-1';
    }
    if (!auth_cookie) {
      auth_cookie = binascii.hexlify(this.transport.rng.read(16));
    }

    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_REQUEST));
    m.add_int(this.remote_chanid);
    m.add_string('x11-req');
    m.add_boolean(true);
    m.add_boolean(single_connection);
    m.add_string(auth_protocol);
    m.add_string(auth_cookie);
    m.add_int(screen_number || 0);
    this.transport._send_user_message(m);
    this.transport._set_x11_handler(handler);
    return auth_cookie;
  },

  /*
    Return the L{Transport} associated with this channel.

    @return: the L{Transport} that was used to create this channel.
    @rtype: L{Transport}
  */
  get_transport : function() {
    return this.transport;
  },

  /*
    Set a name for this channel.  Currently it's only used to set the name
    of the channel in logfile entries.  The name can be fetched with the
    L{get_name} method.

    @param name: new channel name
    @type name: str
  */
  set_name : function(name) {
    this._name = name;
  },

  /*
    Get the name of this channel that was previously set by L{set_name}.

    @return: the name of this channel.
    @rtype: str
  */
  get_name : function() {
    return this._name;
  },

  /*
    Return the ID # for this channel.  The channel ID is unique across
    a L{Transport} and usually a small number.  It's also the number
    passed to L{ServerInterface.check_channel_request} when determining
    whether to accept a channel request in server mode.

    @return: the ID of this channel.
    @rtype: int
  */
  get_id : function() {
    return this.chanid;
  },

  /*
    Set whether stderr should be combined into stdout on this channel.
    The default is C{False}, but in some cases it may be convenient to
    have both streams combined.
    
    If this is C{False}, and L{exec_command} is called (or C{invoke_shell}
    with no pty), output to stderr will not show up through the L{recv}
    and L{recv_ready} calls.  You will have to use L{recv_stderr} and
    L{recv_stderr_ready} to get stderr output.
    
    If this is C{True}, data will never show up via L{recv_stderr} or
    L{recv_stderr_ready}.
    
    @param combine: C{True} if stderr output should be combined into
        stdout on this channel.
    @type combine: bool
    @return: previous setting.
    @rtype: bool
    
    @since: 1.1
  */
  set_combine_stderr : function(combine) {
    var data = '';

    var old = this.combine_stderr;
    this.combine_stderr = combine;
    if (combine && !old) {
      // copy old stderr buffer into primary buffer
      data = this.in_stderr_buffer;
      this.in_stderr_buffer = "";
    }
    if (data.length > 0) {
      this._feed(data);
    }
    return old;
  },


  // socket API


  /*
    Set a timeout on blocking read/write operations.  The C{timeout}
    argument can be a nonnegative float expressing seconds, or C{None}.  If
    a float is given, subsequent channel read/write operations will raise
    a timeout exception if the timeout period value has elapsed before the
    operation has completed.  Setting a timeout of C{None} disables
    timeouts on socket operations.

    C{chan.settimeout(0.0)} is equivalent to C{chan.setblocking(0)};
    C{chan.settimeout(None)} is equivalent to C{chan.setblocking(1)}.

    @param timeout: seconds to wait for a pending read/write operation
        before raising C{socket.timeout}, or C{None} for no timeout.
    @type timeout: float
  */
  settimeout : function(timeout) {
    this.timeout = timeout;
  },

  /*
    Returns the timeout in seconds (as a float) associated with socket
    operations, or C{None} if no timeout is set.  This reflects the last
    call to L{setblocking} or L{settimeout}.

    @return: timeout in seconds, or C{None}.
    @rtype: float
  */
  gettimeout : function() {
    return this.timeout;
  },

  /*
    Set blocking or non-blocking mode of the channel: if C{blocking} is 0,
    the channel is set to non-blocking mode; otherwise it's set to blocking
    mode. Initially all channels are in blocking mode.

    In non-blocking mode, if a L{recv} call doesn't find any data, or if a
    L{send} call can't immediately dispose of the data, an error exception
    is raised. In blocking mode, the calls block until they can proceed. An
    EOF condition is considered "immediate data" for L{recv}, so if the
    channel is closed in the read direction, it will never block.

    C{chan.setblocking(0)} is equivalent to C{chan.settimeout(0)};
    C{chan.setblocking(1)} is equivalent to C{chan.settimeout(None)}.

    @param blocking: 0 to set non-blocking mode; non-0 to set blocking
        mode.
    @type blocking: int
  */
  setblocking : function(blocking) {
    if (blocking) {
      this.settimeout(null);
    } else {
      this.settimeout(0.0);
    }
  },

  /*
    Return the address of the remote side of this Channel, if possible.
    This is just a wrapper around C{'getpeername'} on the Transport, used
    to provide enough of a socket-like interface to allow asyncore to work.
    (asyncore likes to call C{'getpeername'}.)

    @return: the address if the remote host, if known
    @rtype: tuple(str, int)
  */
  getpeername : function() {
    return this.transport.getpeername();
  },

  /*
    Close the channel.  All future read/write operations on the channel
    will fail.  The remote end will receive no more data (after queued data
    is flushed).  Channels are automatically closed when their L{Transport}
    is closed or when they are garbage collected.
  */
  close : function() {
    // only close the pipe when the user explicitly closes the channel.
    // otherwise they will get unpleasant surprises.  (and do it before
    // checking self.closed, since the remote host may have already
    // closed the connection.)
    if (this._pipe) {
      this._pipe.close();
      this._pipe = null;
    }

    if (!this.active || this.closed) {
      return;
    }
    var msgs = this._close_internal();
    for (var x = 0; x < msgs.length; ++x) {
      if (msgs[x]) {
        this.transport._send_user_message(msgs[x]);
      }
    }
  },

  /*
    Returns true if data is buffered and ready to be read from this
    channel.  A C{False} result does not mean that the channel has closed;
    it means you may need to wait before more data arrives.
    
    @return: C{True} if a L{recv} call on this channel would immediately
        return at least one byte; C{False} otherwise.
    @rtype: boolean
  */
  recv_ready : function() {
    return this.in_buffer.length != 0;
  },

  /*
    Receive data from the channel.  The return value is a string
    representing the data received.  The maximum amount of data to be
    received at once is specified by C{nbytes}.  If a string of length zero
    is returned, the channel stream has closed.

    @param nbytes: maximum number of bytes to read.
    @type nbytes: int
    @return: data.
    @rtype: str
    
    @raise socket.timeout: if no data is ready before the timeout set by
        L{settimeout}.
  */
  recv : function(nbytes) {
    if (!this.in_buffer.length) {
      throw new paramikojs.ssh_exception.WaitException("wait");
    }
    var out = this.in_buffer.substring(0, nbytes);
    this.in_buffer = this.in_buffer.substring(nbytes);

    var ack = this._check_add_window(out.length);
    // no need to hold the channel lock when sending this
    if (ack > 0) {
      var m = new paramikojs.Message();
      m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_WINDOW_ADJUST));
      m.add_int(this.remote_chanid);
      m.add_int(ack);
      this.transport._send_user_message(m);
    }

    return out;
  },

  /*
    Returns true if data is buffered and ready to be read from this
    channel's stderr stream.  Only channels using L{exec_command} or
    L{invoke_shell} without a pty will ever have data on the stderr
    stream.
    
    @return: C{True} if a L{recv_stderr} call on this channel would
        immediately return at least one byte; C{False} otherwise.
    @rtype: boolean
    
    @since: 1.1
  */
  recv_stderr_ready : function() {
    return true; //this.in_stderr_buffer.read_ready();
  },

  /*
    Receive data from the channel's stderr stream.  Only channels using
    L{exec_command} or L{invoke_shell} without a pty will ever have data
    on the stderr stream.  The return value is a string representing the
    data received.  The maximum amount of data to be received at once is
    specified by C{nbytes}.  If a string of length zero is returned, the
    channel stream has closed.

    @param nbytes: maximum number of bytes to read.
    @type nbytes: int
    @return: data.
    @rtype: str
    
    @raise socket.timeout: if no data is ready before the timeout set by
        L{settimeout}.
    
    @since: 1.1
  */
  recv_stderr : function(nbytes) {
    if (!this.in_stderr_buffer.length) {
      throw new paramikojs.ssh_exception.WaitException("wait");
    }
    var out = this.in_stderr_buffer.substring(0, nbytes);
    this.in_stderr_buffer = this.in_stderr_buffer.substring(nbytes);
        
    var ack = this._check_add_window(out.length);
    // no need to hold the channel lock when sending this
    if (ack > 0) {
      var m = new paramikojs.Message();
      m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_WINDOW_ADJUST));
      m.add_int(this.remote_chanid);
      m.add_int(ack);
      this.transport._send_user_message(m);
    }

    return out;
  },

  /*
    Returns true if data can be written to this channel without blocking.
    This means the channel is either closed (so any write attempt would
    return immediately) or there is at least one byte of space in the 
    outbound buffer. If there is at least one byte of space in the
    outbound buffer, a L{send} call will succeed immediately and return
    the number of bytes actually written.
    
    @return: C{True} if a L{send} call on this channel would immediately
        succeed or fail
    @rtype: boolean
  */
  send_ready : function() {
    if (this.closed || this.eof_sent) {
      return true;
    }
    return this.out_window_size > 0;
  },

  /*
    Send data to the channel.  Returns the number of bytes sent, or 0 if
    the channel stream is closed.  Applications are responsible for
    checking that all data has been sent: if only some of the data was
    transmitted, the application needs to attempt delivery of the remaining
    data.

    @param s: data to send
    @type s: str
    @return: number of bytes actually sent
    @rtype: int

    @raise socket.timeout: if no data could be sent before the timeout set
        by L{settimeout}.
  */
  send : function(s) {
    var size = s.length;
    size = this._wait_for_send_window(size);
    if (size == 0) {
      // eof or similar
      return 0;
    }
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_DATA));
    m.add_int(this.remote_chanid);
    m.add_string(s.substring(0, size));
    this.transport._send_user_message(m);
    return size;
  },

  /*
    Send data to the channel on the "stderr" stream.  This is normally
    only used by servers to send output from shell commands -- clients
    won't use this.  Returns the number of bytes sent, or 0 if the channel
    stream is closed.  Applications are responsible for checking that all
    data has been sent: if only some of the data was transmitted, the
    application needs to attempt delivery of the remaining data.
    
    @param s: data to send.
    @type s: str
    @return: number of bytes actually sent.
    @rtype: int
    
    @raise socket.timeout: if no data could be sent before the timeout set
        by L{settimeout}.
    
    @since: 1.1
  */
  send_stderr : function(s) {
    var size = s.length;
    size = this._wait_for_send_window(size);
    if (size == 0) {
      // eof or similar
      return 0;
    }
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_EXTENDED_DATA));
    m.add_int(this.remote_chanid);
    m.add_int(1);
    m.add_string(s.substring(0, size));
    this.transport._send_user_message(m);
    return size;
  },

  /*
    Send data to the channel, without allowing partial results.  Unlike
    L{send}, this method continues to send data from the given string until
    either all data has been sent or an error occurs.  Nothing is returned.

    @param s: data to send.
    @type s: str

    @raise socket.timeout: if sending stalled for longer than the timeout
        set by L{settimeout}.
    @raise socket.error: if an error occured before the entire string was
        sent.
    
    @note: If the channel is closed while only part of the data hase been
        sent, there is no way to determine how much data (if any) was sent.
        This is irritating, but identically follows python's API.
  */
  sendall : function(s) {
    while (s) {
      if (this.closed) {
        // this doesn't seem useful, but it is the documented behavior of Socket
        throw 'Socket is closed';
      }
      var sent = this.send(s);
      s = s.substring(sent);
    }
    return null;
  },

  /*
    Send data to the channel's "stderr" stream, without allowing partial
    results.  Unlike L{send_stderr}, this method continues to send data
    from the given string until all data has been sent or an error occurs.
    Nothing is returned.
    
    @param s: data to send to the client as "stderr" output.
    @type s: str
    
    @raise socket.timeout: if sending stalled for longer than the timeout
        set by L{settimeout}.
    @raise socket.error: if an error occured before the entire string was
        sent.
        
    @since: 1.1
  */
  sendall_stderr : function(s) {
    while (s) {
      if (this.closed) {
        throw 'Socket is closed';
      }
      sent = this.send_stderr(s);
      s = s.substring(sent);
    }
    return null;
  },

  /*
    Return a file-like object associated with this channel.  The optional
    C{mode} and C{bufsize} arguments are interpreted the same way as by
    the built-in C{file()} function in python.

    @return: object which can be used for python file I/O.
    @rtype: L{ChannelFile}
  */
  makefile : function() {
    return paramikojs.ChannelFile([this] + arguments);
  },

  /*
    Return a file-like object associated with this channel's stderr
    stream.   Only channels using L{exec_command} or L{invoke_shell}
    without a pty will ever have data on the stderr stream.
    
    The optional C{mode} and C{bufsize} arguments are interpreted the
    same way as by the built-in C{file()} function in python.  For a
    client, it only makes sense to open this file for reading.  For a
    server, it only makes sense to open this file for writing.
    
    @return: object which can be used for python file I/O.
    @rtype: L{ChannelFile}

    @since: 1.1
  */
  makefile_stderr : function() {
    return paramikojs.ChannelStderrFile([this] + arguments);
  },

  /*
    Shut down one or both halves of the connection.  If C{how} is 0,
    further receives are disallowed.  If C{how} is 1, further sends
    are disallowed.  If C{how} is 2, further sends and receives are
    disallowed.  This closes the stream in one or both directions.

    @param how: 0 (stop receiving), 1 (stop sending), or 2 (stop
        receiving and sending).
    @type how: int
  */
  shutdown : function(how) {
    if (how == 0 || how == 2) {
      // feign "read" shutdown
      this.eof_received = 1;
    }
    if (how == 1 || how == 2) {
      var m = this._send_eof();
      if (m) {
        this.transport._send_user_message(m);
      }
    }
  },

  /*
    Shutdown the receiving side of this socket, closing the stream in
    the incoming direction.  After this call, future reads on this
    channel will fail instantly.  This is a convenience method, equivalent
    to C{shutdown(0)}, for people who don't make it a habit to
    memorize unix constants from the 1970s.
    
    @since: 1.2
  */
  shutdown_read : function() {
    this.shutdown(0);
  },

  /*
    Shutdown the sending side of this socket, closing the stream in
    the outgoing direction.  After this call, future writes on this
    channel will fail instantly.  This is a convenience method, equivalent
    to C{shutdown(1)}, for people who don't make it a habit to
    memorize unix constants from the 1970s.
    
    @since: 1.2
  */
  shutdown_write : function() {
    this.shutdown(1);
  },


  //  calls from Transport


  _set_transport : function(transport) {
    this.transport = transport;
  },

  _set_window : function(window_size, max_packet_size) {
    this.in_window_size = window_size;
    this.in_max_packet_size = max_packet_size;
    // threshold of bytes we receive before we bother to send a window update
    this.in_window_threshold = parseInt(window_size / 10);
    this.in_window_sofar = 0;
    this._log(DEBUG, 'Max packet in: ' + max_packet_size + ' bytes');
  },
    
  _set_remote_channel : function(chanid, window_size, max_packet_size) {
    this.remote_chanid = chanid;
    this.out_window_size = window_size;
    this.out_max_packet_size = Math.max(max_packet_size, paramikojs.Channel.MIN_PACKET_SIZE);
    this.active = 1;
    this._log(DEBUG, 'Max packet out: ' + max_packet_size + ' bytes');
  },
    
  _request_success : function(m) {
    this._log(DEBUG, 'Sesch channel ' + this.chanid + ' request ok');
  },

  _request_failed : function(m) {
    var msgs = this._close_internal();

    for (var x = 0; x < msgs.length; ++x) {
      if (msgs[x]) {
        this.transport._send_user_message(msgs[x]);
      }
    }
  },

  _feed : function(m) {
    var s;
    if (typeof m == "string") {
      // passed from _feed_extended
      s = m;
    } else {
      s = m.get_string();
    }
    this.in_buffer += s;
  },

  _feed_extended : function(m) {
    var code = m.get_int();
    var s = m.get_string();
    if (code != 1) {
      this._log(ERROR, 'unknown extended_data type ' + code + '; discarding');
      return;
    }
    if (this.combine_stderr) {
      this._feed(s);
    } else {
      this.in_stderr_buffer += s;
    }
  },
    
  _window_adjust : function(m) {
    var nbytes = m.get_int();
    if (this.ultra_debug) {
      this._log(DEBUG, 'window up ' + nbytes);
    }
    this.out_window_size += nbytes;
  },

  _handle_request : function(m) {
    var key = m.get_string();
    var want_reply = m.get_boolean();
    var server = this.transport.server_object;
    var ok = false;
    if (key == 'exit-status') {
      this.exit_status = m.get_int();
      ok = true;
    } else if (key == 'xon-xoff') {
      // ignore
      ok = true;
    } else if (key == 'pty-req') {
      var term = m.get_string();
      var width = m.get_int();
      var height = m.get_int();
      var pixelwidth = m.get_int();
      var pixelheight = m.get_int();
      var modes = m.get_string();
      if (!server) {
        ok = false;
      } else {
        ok = server.check_channel_pty_request(this, term, width, height, pixelwidth, pixelheight, modes);
      }
    } else if (key == 'shell') {
      if (!server) {
        ok = false;
      } else {
        ok = server.check_channel_shell_request(this);
      }
    } else if (key == 'exec') {
      var cmd = m.get_string();
      if (!server) {
        ok = false;
      } else {
        ok = server.check_channel_exec_request(this, cmd);
      }
    } else if (key == 'subsystem') {
      var name = m.get_string();
      if (!server) {
        ok = false;
      } else {
        ok = server.check_channel_subsystem_request(this, name);
      }
    } else if (key == 'window-change') {
      var width = m.get_int();
      var height = m.get_int();
      var pixelwidth = m.get_int();
      var pixelheight = m.get_int();
      if (!server) {
        ok = false;
      } else {
        ok = server.check_channel_window_change_request(this, width, height, pixelwidth, pixelheight);
      }
    } else if (key == 'x11-req') {
      var single_connection = m.get_boolean();
      var auth_proto = m.get_string();
      var auth_cookie = m.get_string();
      var screen_number = m.get_int();
      if (!server) {
        ok = false;
      } else {
        ok = server.check_channel_x11_request(this, single_connection, auth_proto, auth_cookie, screen_number);
      }
    } else {
      this._log(DEBUG, 'Unhandled channel request "' + key + '"');
      ok = false;
    }
    if (want_reply) {
      var m = new paramikojs.Message();
      if (ok) {
        m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_SUCCESS));
      } else {
        m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_FAILURE));
      }
      m.add_int(this.remote_chanid);
      this.transport._send_user_message(m);
    }
  },

  _handle_eof : function(m) {
    if (!this.eof_received) {
      this.eof_received = true;
      this.in_buffer = "";
      this.in_stderr_buffer = "";
      if (this._pipe) {
        this._pipe.set_forever();
      }
    }
    this._log(DEBUG, 'EOF received (' + this._name + ')');
  },

  _handle_close : function(m) {
    var msgs = this._close_internal();
    this.transport._unlink_channel(this.chanid);

    for (var x = 0; x < msgs.length; ++x) {
      if (msgs[x]) {
        this.transport._send_user_message(msgs[x]);
      }
    }
  },


  //  internals...

  _log : function(level, msg) {
    this.logger.log(level, msg);
  },

  _set_closed : function() {
    this.closed = true;
    this.in_buffer = "";
    this.in_stderr_buffer = "";
  },

  _send_eof : function() {
    if (this.eof_sent) {
      return null;
    }
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_EOF));
    m.add_int(this.remote_chanid);
    this.eof_sent = true;
    this._log(DEBUG, 'EOF sent (' + this._name + ')');
    return m;
  },

  _close_internal : function() {
    if (!this.active || this.closed) {
      return [null, null];
    }
    var m1 = this._send_eof();
    var m2 = new paramikojs.Message();
    m2.add_byte(String.fromCharCode(paramikojs.MSG_CHANNEL_CLOSE));
    m2.add_int(this.remote_chanid);
    this._set_closed();
    // can't unlink from the Transport yet -- the remote side may still
    // try to send meta-data (exit-status, etc)
    return [m1, m2];
  },

  _unlink : function() {
    // server connection could die before we become active: still signal the close!
    if (this.closed) {
      return;
    }
    this._set_closed();
    this.transport._unlink_channel(this.chanid);
  },

  _check_add_window : function(n) {
    if (this.closed || this.eof_received || !this.active) {
      return 0;
    }
    if (this.ultra_debug) {
      this._log(DEBUG, 'addwindow ' + n);
    }
    this.in_window_sofar += n;
    if (this.in_window_sofar <= this.in_window_threshold) {
      return 0;
    }
    if (this.ultra_debug) {
      this._log(DEBUG, 'addwindow send ' + this.in_window_sofar);
    }
    var out = this.in_window_sofar;
    this.in_window_sofar = 0;
    return out;
  },

  /*
    Wait for the send window to open up, and allocate up to C{size} bytes
    for transmission.  If no space opens up before the timeout, a timeout
    exception is raised.  Returns the number of bytes available to send
    (may be less than requested).
  */
  _wait_for_send_window : function(size) {
    if (this.closed || this.eof_sent) {
      return 0;
    }
    if (this.out_window_size == 0) {
      throw new paramikojs.ssh_exception.WaitException("wait");
    }
    // we have some window to squeeze into
    if (this.closed || this.eof_sent) {
      return 0;
    }
    if (this.out_window_size < size) {
      size = this.out_window_size;
    }
    if (this.out_max_packet_size - 64 < size) {
      size = this.out_max_packet_size - 64;
    }
    this.out_window_size -= size;
    if (this.ultra_debug) {
      this._log(DEBUG, 'window down to ' + this.out_window_size);
    }
    return size;
  }
};


/*
  A file-like wrapper around L{Channel}.  A ChannelFile is created by calling
  L{Channel.makefile}.

  @bug: To correctly emulate the file object created from a socket's
      C{makefile} method, a L{Channel} and its C{ChannelFile} should be able
      to be closed or garbage-collected independently.  Currently, closing
      the C{ChannelFile} does nothing but flush the buffer.
*/
paramikojs.ChannelFile = function(channel, mode, bufsize) {
  inherit(this, new paramikojs.BufferedFile());

  mode = mode || 'r';
  bufsize = bufsize || -1;
  this.channel = channel;
  this._set_mode(mode, bufsize);
}

paramikojs.ChannelFile.prototype = {
  _read : function(size) {
    return this.channel.recv(size);
  },

  _write : function(data) {
    this.channel.sendall(data);
    return data.length;
  }
};

paramikojs.ChannelStderrFile = function(channel, mode, bufsize) {
  mode = mode || 'r';
  bufsize = bufsize || -1;

  inherit(this, new paramikojs.ChannelFile(channel, mode, bufsize));
}

paramikojs.ChannelStderrFile.prototype = {
  _read : function(size) {
    return this.channel.recv_stderr(size);
  },

  _write : function(data) {
    this.channel.sendall_stderr(data);
    return data.length;
  }
};
