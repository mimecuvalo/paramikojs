/*
  Implementation of the base SSH packet protocol.
*/

paramikojs.Packetizer = function(socket) {
  this.__socket = socket;
  this.__logger = null;
  this.__closed = false;
  this.__dump_packets = false;
  this.__need_rekey = false;
  this.__init_count = 0;
  this.__remainder = '';
  this.__decrypted_header = '';

  // used for noticing when to re-key:
  this.__sent_bytes = 0;
  this.__sent_packets = 0;
  this.__received_bytes = 0;
  this.__received_packets = 0;
  this.__received_packets_overflow = 0;

  // current inbound/outbound ciphering:
  this.__block_size_out = 8;
  this.__block_size_in = 8;
  this.__mac_size_out = 0;
  this.__mac_size_in = 0;
  this.__block_engine_out = null;
  this.__block_engine_in = null;
  this.__mac_engine_out = null;
  this.__mac_engine_in = null;
  this.__mac_key_out = '';
  this.__mac_key_in = '';
  this.__compress_engine_out = null;
  this.__compress_engine_in = null;
  this.__sequence_number_out = 0;
  this.__sequence_number_in = 0;

  // keepalives:
  this.__keepalive_interval = 0;
  this.__keepalive_last = new Date();
  this.__keepalive_callback = null;
}

paramikojs.Packetizer.prototype = {
	// READ the secsh RFC's before raising these values.  if anything,
  // they should probably be lower.
  REKEY_PACKETS : Math.pow(2, 29),
  REKEY_BYTES : Math.pow(2, 29),
  REKEY_PACKETS_OVERFLOW_MAX : Math.pow(2, 29),   // Allow receiving this many packets after a re-key request before terminating
  REKEY_BYTES_OVERFLOW_MAX : Math.pow(2, 29),     // Allow receiving this many bytes after a re-key request before terminating

  set_log : function(log) {
    this.__logger = log;
  },

  /*
    Switch outbound data cipher.
  */
  set_outbound_cipher : function(block_engine, block_size, mac_engine, mac_size, mac_key) {
    this.__block_engine_out = block_engine;
    this.__block_size_out = block_size;
    this.__mac_engine_out = mac_engine;
    this.__mac_size_out = mac_size;
    this.__mac_key_out = mac_key;
    this.__sent_bytes = 0;
    this.__sent_packets = 0;
    // wait until the reset happens in both directions before clearing rekey flag
    this.__init_count |= 1;
    if (this.__init_count == 3) {
      this.__init_count = 0;
      this.__need_rekey = false;
    }
  },

  /*
    Switch inbound data cipher.
  */
  set_inbound_cipher : function(block_engine, block_size, mac_engine, mac_size, mac_key) {
    this.__block_engine_in = block_engine;
    this.__block_size_in = block_size;
    this.__mac_engine_in = mac_engine;
    this.__mac_size_in = mac_size;
    this.__mac_key_in = mac_key;
    this.__received_bytes = 0;
    this.__received_packets = 0;
    this.__received_bytes_overflow = 0;
    this.__received_packets_overflow = 0;
    // wait until the reset happens in both directions before clearing rekey flag
    this.__init_count |= 2;
    if (this.__init_count == 3) {
      this.__init_count = 0;
      this.__need_rekey = false;
    }
  },

  set_outbound_compressor : function(compressor) {
    this.__compress_engine_out = compressor;
  },

  set_inbound_compressor : function(compressor) {
    this.__compress_engine_in = compressor;
  },

  close : function() {
    this.__closed = true;
  },

  set_hexdump : function(hexdump) {
    this.__dump_packets = hexdump;
  },

  get_hexdump : function() {
    return this.__dump_packets;
  },

  get_mac_size_in : function() {
    return this.__mac_size_in;
  },

  get_mac_size_out : function() {
    return this.__mac_size_out;
  },

  /*
    Returns C{True} if a new set of keys needs to be negotiated.  This
    will be triggered during a packet read or write, so it should be
    checked after every read or write, or at least after every few.

    @return: C{True} if a new set of keys needs to be negotiated
  */
  need_rekey : function() {
    return this.__need_rekey;
  },

  /*
    Turn on/off the callback keepalive.  If C{interval} seconds pass with
    no data read from or written to the socket, the callback will be
    executed and the timer will be reset.
  */
  set_keepalive : function(interval, callback) {
    this.__keepalive_interval = interval;
    this.__keepalive_callback = callback;
    this.__keepalive_last = new Date();
  },

  /*
    Read as close to N bytes as possible, blocking as long as necessary.

    @param n: number of bytes to read
    @type n: int
    @return: the data read
    @rtype: str
    @raise EOFError: if the socket was closed before all the bytes could
        be read
  */
  read_all : function(n, check_rekey) {
    //if (this.__remainder.length + this.__socket.fullBuffer.length < n) {
    if (this.__socket.fullBuffer.length < n) {
      throw new paramikojs.ssh_exception.WaitException("wait");
    }

    var out = '';
    // handle over-reading from reading the banner line
    /*if (this.__remainder.length > 0) {
      out = this.__remainder.substring(0, n);
      this.__remainder = this.__remainder.substring(n);
      n -= out.length;
    }*/
    out += this.__socket.fullBuffer.substring(0, n);
    this.__socket.fullBuffer = this.__socket.fullBuffer.substring(n);
    return out;
  },

  write_all : function(out) {
    this.__keepalive_last = new Date();
    //this.__socket.writeControl(out);
    this.__socket.writeCallback(out);
  },

  /*
    Read a line from the socket.  We assume no data is pending after the
    line, so it's okay to attempt large reads.
  */
  readline : function(timeout) {
    //var buf = this.__remainder;
    var buf = '';
    while (buf.indexOf('\n') == -1) {
      buf += this._read_timeout(timeout);
    }
    var n = buf.indexOf('\n');
    this.__socket.fullBuffer = buf.substring(n + 1) + this.__socket.fullBuffer;
    buf = buf.substring(0, n);
    if (buf.length > 0 && buf.charAt(buf.length - 1) == '\r') {
      buf = buf.substring(0, buf.length - 1);
    }
    return buf;
  },

  /*
    Write a block of data using the current cipher, as an SSH block.
  */
  send_message : function(data) {
    // encrypt this sucka
    data = data.toString();
    var cmd = data[0].charCodeAt(0);
    var cmd_name;
    if (cmd in paramikojs.MSG_NAMES) {
      cmd_name = paramikojs.MSG_NAMES[cmd];
    } else {
      cmd_name = '$' + cmd;
    }
    var orig_len = data.length;
    if (this.__compress_engine_out) {
      data = this.__compress_engine_out.compress(data);
    }
    var packet = this._build_packet(data);
    if (this.__dump_packets) {
      this._log(DEBUG, 'Write packet <' + cmd_name + '>, length ' + orig_len);
      this._log(DEBUG, paramikojs.util.format_binary(packet, 'OUT: '));
    }
    var out;
    if (this.__block_engine_out) {
      out = this.__block_engine_out.encrypt(packet);
    } else {
      out = packet;
    }

    // + mac
    var payload;
    if (this.__block_engine_out) {
      payload = struct.pack('>I', this.__sequence_number_out) + packet;
      out += kryptos.hash.HMAC(this.__mac_key_out, payload, this.__mac_engine_out).substring(0, this.__mac_size_out);
    }
    this.__sequence_number_out = (this.__sequence_number_out + 1) & 0xffffffff;
    this.write_all(out);

    this.__sent_bytes += out.length;
    this.__sent_packets += 1;
    if ((this.__sent_packets >= this.REKEY_PACKETS || this.__sent_bytes >= this.REKEY_BYTES)
           && !this.__need_rekey) {
      // only ask once for rekeying
      this._log(DEBUG, 'Rekeying (hit ' + this.__sent_packets + ' packets, ' + this.__sent_bytes + ' bytes sent)');
      this.__received_bytes_overflow = 0;
      this.__received_packets_overflow = 0;
      this._trigger_rekey();
    }
  },

  /*
    Only one thread should ever be in this function (no other locking is
    done).

    @raise SSHException: if the packet is mangled
    @raise NeedRekeyException: if the transport should rekey
  */
  read_message : function() {
    var header;
    if (!this.__decrypted_header) {
      header = this.read_all(this.__block_size_in, true);
      if (this.__block_engine_in) {
        header = this.__block_engine_in.decrypt(header);
      }
      if (this.__dump_packets) {
        this._log(DEBUG, paramikojs.util.format_binary(header, 'IN: '));
      }
    } else {
      header = this.__decrypted_header;
      this.__decrypted_header = '';
    }

    var packet_size = struct.unpack('>I', header.substring(0, 4))[0];
    // leftover contains decrypted bytes from the first block (after the length field)
    var leftover = header.substring(4);
    if ((packet_size - leftover.length) % this.__block_size_in != 0) {
      throw new paramikojs.ssh_exception.SSHException('Invalid packet blocking');
    }

    var buf;
    try {
      buf = this.read_all(packet_size + this.__mac_size_in - leftover.length);
    } catch(ex) {
      if (ex instanceof paramikojs.ssh_exception.WaitException) {
        // not enough data yet to complete the packet
        this.__decrypted_header = header;
        throw new paramikojs.ssh_exception.WaitException("wait"); // rethrow exception
      } else {
        throw ex;
      }
    }

    var packet = buf.substring(0, packet_size - leftover.length);
    var post_packet = buf.substring(packet_size - leftover.length);
    if (this.__block_engine_in && packet) {
      packet = this.__block_engine_in.decrypt(packet);
    }
    if (this.__dump_packets) {
      this._log(DEBUG, paramikojs.util.format_binary(packet, 'IN: '));
    }
    packet = leftover + packet;

    if (this.__mac_size_in > 0) {
      var mac = post_packet.substring(0, this.__mac_size_in);
      var mac_payload = struct.pack('>I', this.__sequence_number_in) + struct.pack('>I', packet_size) + packet;
      var my_mac = kryptos.hash.HMAC(this.__mac_key_in, mac_payload, this.__mac_engine_in).substring(0, this.__mac_size_in);
      if (my_mac != mac) {
        throw new paramikojs.ssh_exception.SSHException('Mismatched MAC');
      }
    }
    var padding = packet[0].charCodeAt(0);
    var payload = packet.substring(1, packet_size - padding);
    if (this.__dump_packets) {
      this._log(DEBUG, 'Got payload (' + packet_size + ' bytes, ' + padding + ' padding)');
    }

    if (this.__compress_engine_in) {
      payload = this.__compress_engine_in.decompress(payload);
    }

    var msg = new paramikojs.Message(payload.substring(1));
    msg.seqno = this.__sequence_number_in;
    this.__sequence_number_in = (this.__sequence_number_in + 1) & 0xffffffff;

    // check for rekey
    var raw_packet_size = packet_size + this.__mac_size_in + 4;
    this.__received_bytes += raw_packet_size;
    this.__received_packets += 1;
    if (this.__need_rekey) {
      // we've asked to rekey -- give them some packets to comply before
      // dropping the connection
      this.__received_bytes_overflow += raw_packet_size;
      this.__received_packets_overflow += 1;
      if (this.__received_packets_overflow >= this.REKEY_PACKETS_OVERFLOW_MAX ||
          this.__received_bytes_overflow >= this.REKEY_BYTES_OVERFLOW_MAX) {
        throw new paramikojs.ssh_exception.SSHException('Remote transport is ignoring rekey requests');
      }
    } else if (this.__received_packets >= this.REKEY_PACKETS ||
      this.__received_bytes >= this.REKEY_BYTES) {
      // only ask once for rekeying
      this._log(DEBUG, 'Rekeying (hit ' + this.__received_packets + ' packets, ' + this.__received_bytes + ' bytes received)');
      this.__received_bytes_overflow = 0;
      this.__received_packets_overflow = 0;
      this._trigger_rekey();
    }

    var cmd = payload[0].charCodeAt(0);
    var cmd_name;
    if (cmd in paramikojs.MSG_NAMES) {
      cmd_name = paramikojs.MSG_NAMES[cmd];
    } else {
      cmd_name = '$' + cmd;
    }
    if (this.__dump_packets) {
      this._log(DEBUG, 'Read packet <' + cmd_name + '>, length ' + payload.length);
    }
    if (false) {
      this.__socket.run({ 'ptype': cmd, 'm': msg });
    }
    return { 'ptype': cmd, 'm': msg };
  },


  //  protected

  _log : function(level, msg) {
    this.__logger.log(level, msg);
  },

  _check_keepalive : function() {
    if (!this.__keepalive_interval || !this.__block_engine_out || this.__need_rekey) {
      // wait till we're encrypting, and not in the middle of rekeying
      return;
    }
    var now = new Date();
    if (now > this.__keepalive_last + this.__keepalive_interval) {
      this.__keepalive_callback();
      this.__keepalive_last = now;
    }
  },

  _read_timeout : function(timeout) {
    var buf = this.__socket.fullBuffer.substring(0, 128);
    this.__socket.fullBuffer = this.__socket.fullBuffer.substring(128);
    return buf;
  },

  _build_packet : function(payload) {
    // pad up at least 4 bytes, to nearest block-size (usually 8)
    var bsize = this.__block_size_out;
    var padding = 3 + bsize - ((payload.length + 8) % bsize);
    var packet = struct.pack('>I', payload.length + padding + 1) + struct.pack('>B', padding);
    packet += payload;
    if (this.__block_engine_out) {
      packet += this.__socket.rng.read(padding, true);
    } else {
      // cute trick i caught openssh doing: if we're not encrypting,
      // don't waste random bytes for the padding
      packet += new Array(padding + 1).join('\x00');
    }
    return packet;
  },

  _trigger_rekey : function() {
    // outside code should check for this flag
    this.__need_rekey = true;
  }

};
