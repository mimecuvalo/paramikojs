paramikojs.BaseSFTP = function () {
  this.logger = paramikojs.util.get_logger();
  this.ultra_debug = false;
}

paramikojs.BaseSFTP.prototype = {
	CMD_INIT : 1,
  CMD_VERSION : 2,
  CMD_OPEN : 3,
  CMD_CLOSE : 4,
  CMD_READ : 5,
  CMD_WRITE : 6,
  CMD_LSTAT : 7,
  CMD_FSTAT : 8,
  CMD_SETSTAT : 9,
  CMD_FSETSTAT : 10,
  CMD_OPENDIR : 11,
  CMD_READDIR : 12,
  CMD_REMOVE : 13,
  CMD_MKDIR : 14,
  CMD_RMDIR : 15,
  CMD_REALPATH : 16,
  CMD_STAT : 17,
  CMD_RENAME : 18,
  CMD_READLINK : 19,
  CMD_SYMLINK : 20,

  CMD_STATUS : 101,
  CMD_HANDLE : 102,
  CMD_DATA : 103,
  CMD_NAME : 104,
  CMD_ATTRS : 105,

  CMD_EXTENDED : 200,
  CMD_EXTENDED_REPLY : 201,

  SFTP_OK : 0,
  SFTP_EOF : 1,
  SFTP_NO_SUCH_FILE : 2,
  SFTP_PERMISSION_DENIED : 3,
  SFTP_FAILURE : 4,
  SFTP_BAD_MESSAGE : 5,
  SFTP_NO_CONNECTION : 6,
  SFTP_CONNECTION_LOST : 7,
  SFTP_OP_UNSUPPORTED : 8,

  SFTP_DESC : [ 'Success',
              'End of file',
              'No such file',
              'Permission denied',
              'Failure',
              'Bad message',
              'No connection',
              'Connection lost',
              'Operation unsupported' ],

  SFTP_FLAG_READ : 0x1,
  SFTP_FLAG_WRITE : 0x2,
  SFTP_FLAG_APPEND : 0x4,
  SFTP_FLAG_CREATE : 0x8,
  SFTP_FLAG_TRUNC : 0x10,
  SFTP_FLAG_EXCL : 0x20,

  _VERSION : 3,


  // for debugging
  CMD_NAMES : {
    1: 'init',
    2: 'version',
    3: 'open',
    4: 'close',
    5: 'read',
    6: 'write',
    7: 'lstat',
    8: 'fstat',
    9: 'setstat',
    10: 'fsetstat',
    11: 'opendir',
    12: 'readdir',
    13: 'remove',
    14: 'mkdir',
    15: 'rmdir',
    16: 'realpath',
    17: 'stat',
    18: 'rename',
    19: 'readlink',
    20: 'symlink',
    101: 'status',
    102: 'handle',
    103: 'data',
    104: 'name',
    105: 'attrs',
    200: 'extended',
    201: 'extended_reply'
  },


  //  internals...

  _send_version : function(callback) {
    var self = this;
    var send_packet_callback = function() {
      self._send_version_callback(callback);
    };
    this._send_packet(this.CMD_INIT, struct.pack('>I', this._VERSION), send_packet_callback);
  },

  _send_version_callback : function(callback) {
    try {
      var packet = this._read_packet();
    } catch(ex) {
      if (ex instanceof paramikojs.ssh_exception.WaitException) {
        // waiting on socket
        var self = this;
        var wait_callback = function() { self._send_version_callback(callback) };
        setTimeout(wait_callback, 10);
        return;
      } else {
        throw ex;
      }
    }

    if (packet[0] != this.CMD_VERSION) {
      throw 'Incompatible sftp protocol';
    }
    var version = struct.unpack('>I', packet[1].substring(0, 4))[0];
    //        if version != _VERSION:
    //            raise SFTPError('Incompatible sftp protocol')
    callback(version);
  },

  _send_server_version : function() {
    // winscp will freak out if the server sends version info before the
    // client finishes sending INIT.
    var packet = this._read_packet();
    if (t != this.CMD_INIT) {
      throw 'Incompatible sftp protocol';
    }
    var version = struct.unpack('>I', packet[0].substring(0, 4))[0];
    // advertise that we support "check-file"
    var extension_pairs = [ 'check-file', 'md5,sha1' ];
    var msg = new paramikojs.Message();
    msg.add_int(this._VERSION);
    msg.add(extension_pairs);
    this._send_packet(this.CMD_VERSION, msg.toString());
    return version;
  },

  _log : function(level, msg) {
    this.logger.log(level, msg);
  },

  _write_all : function(out, send_packet_callback) {
    while (out.length > 0) {
      try {
        var n = this.sock.send(out);
      } catch(ex) {
        if (ex instanceof paramikojs.ssh_exception.WaitException) {
          // waiting on window adjust
          var self = this;
          var wait_callback = function() { self._write_all(out, send_packet_callback) };
          setTimeout(wait_callback, 10);
          return;
        } else {
          throw ex;
        }
      }
      if (n <= 0) {
        throw new paramikojs.ssh_exception.EOFError();
      }
      if (n == out.length) {
        if (send_packet_callback) {
          send_packet_callback();
        }
        return;
      }
      out = out.substring(n);
    }
  },

  _read_all : function(n) {
    var out = this.sock.recv(n);
    if (out.length < n) {
      // waiting on socket
      this.sock.in_buffer = out + this.sock.in_buffer;              // add data back into in_buffer
      throw new paramikojs.ssh_exception.WaitException("wait");
    }
    return out;
  },

  _send_packet : function(t, packet, send_packet_callback) {
    //self._log(DEBUG2, 'write: %s (len=%d)' % (CMD_NAMES.get(t, '0x%02x' % t), len(packet)))
    this.logger.log(DEBUG, 'write: ' + this.CMD_NAMES[t] + '(len=' + packet.length + ')');
    var out = struct.pack('>I', packet.length + 1) + String.fromCharCode(t) + packet;
    if (this.ultra_debug) {
      this.logger.log(DEBUG, paramikojs.util.format_binary(out, 'OUT: '));
    }
    this._write_all(out, send_packet_callback);
  },

  _read_packet : function() {
    var x = this._read_all(4);
    // most sftp servers won't accept packets larger than about 32k, so
    // anything with the high byte set (> 16MB) is just garbage.
    if (x[0] != '\x00') {
      throw 'Garbage packet received';
    }
    var size = struct.unpack('>I', x)[0];
    try {
      var data = this._read_all(size);
    } catch(ex) {
      if (ex instanceof paramikojs.ssh_exception.WaitException) {
        // waiting on socket
        this.sock.in_buffer = x + this.sock.in_buffer;              // add header back into in_buffer
        throw new paramikojs.ssh_exception.WaitException("wait");   // rethrow exception
      } else {
        throw ex;
      }
    }
    if (this.ultra_debug) {
      this.logger.log(DEBUG, paramikojs.util.format_binary(data, 'IN: '));
    }
    if (size > 0) {
      var t = data[0].charCodeAt(0);
      this.logger.log(DEBUG, 'read: ' + this.CMD_NAMES[t] + '(len=' + (data.length - 1) + ')');
      return [t, data.substring(1)];
    }
    return [0, ''];
  }
};
