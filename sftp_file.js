// todo fixme: when mozilla supports files over 4GB (2GB for uploads)
// the variables _realpos, offset, and length need to be converted to BigIntegers
//

/*
  Proxy object for a file on the remote server, in client mode SFTP.
*/
paramikojs.SFTPFile = function(sftp, handle, mode, bufsize, current_size) {
  inherit(this, new paramikojs.BufferedFile());

  mode = mode || 'r';
  bufsize = bufsize || -1;
  current_size = current_size || 0;

  this.sftp = sftp;
  this.handle = handle;
  // NOTE(mime): b/c we avoid doing stat() in get_size we have to set the _size manually for appending to work properly
  this._size = current_size;
  this._set_mode(mode, bufsize);
  this.mode = mode;
  this.bufsize = bufsize;
  this.pipelined = false;
  this._prefetching = false;
  this._prefetch_done = false;
  this._prefetch_data = {};
  this._prefetch_reads = [];
  this._saved_exception = null;
}

paramikojs.SFTPFile.prototype = {
  // Some sftp servers will choke if you send read/write requests larger than
  // this size.
  MAX_REQUEST_SIZE : 32768,

  close : function(callback) {
    this._close(false, callback);
  },

  _close : function(async, callback) {
    // We allow double-close without signaling an error, because real
    // Python file objects do.  However, we must protect against actually
    // sending multiple CMD_CLOSE packets, because after we close our
    // handle, the same handle may be re-allocated by the server, and we
    // may end up mysteriously closing some random other file.  (This is
    // especially important because we unconditionally call close() from
    // __del__.)
    if (this._closed) {
      return;
    }
    this.sftp._log(DEBUG, 'close(' + paramikojs.util.hexify(this.handle) + ')');
    if (this.pipelined) {
      this.sftp._finish_responses(this);
    }
    this.__close();
    try {
      if (async) {
        // GC'd file handle could be called from an arbitrary thread -- don't wait for a response
        this.sftp._async_request(null, this.sftp.CMD_CLOSE, null, [this.handle]);
      } else {
        this.sftp._request(this.sftp.CMD_CLOSE, callback, this.handle);
      }
    } catch(ex) {
      // pass
    }
  },

  _data_in_prefetch_requests : function(offset, size) {
    var k = [];
    for (var x = 0; x < this._prefetch_reads.length; ++x) {
      if (this._prefetch_reads[x][0] <= offset) {
        k.push(this._prefetch_reads[x]);
      }
    }
    if (k.length == 0) {
      return false;
    }
    function compare(x, y) {
      if (x[0] < y[0]) {
        return -1;
      }
      if (x[0] > y[0]) {
        return 1;
      }
      return 0;
    }
    k.sort(compare);
    var buf_offset = k[k.length - 1];
    var buf_size = k[k.length - 1];
    if (buf_offset + buf_size <= offset) {
      // prefetch request ends before this one begins
      return false;
    }
    if (buf_offset + buf_size >= offset + size) {
      // inclusive
      return true;
    }
    // well, we have part of the request.  see if another chunk has the rest.
    return this._data_in_prefetch_requests(buf_offset + buf_size, offset + size - buf_offset - buf_size);
  },

  /*
    if a block of data is present in the prefetch buffers, at the given
    offset, return the offset of the relevant prefetch buffer.  otherwise,
    return None.  this guarantees nothing about the number of bytes
    collected in the prefetch buffer so far.
  */
  _data_in_prefetch_buffers : function(offset) {
    var k = [];
    var index = null;
    for (var i in this._prefetch_data) {
      if (i <= offset) {
        k.push(i);
        if (!index || i > index) {
          index = i;
        }
      }
    }
    if (k.length == 0) {
      return null;
    }
    var buf_offset = offset - index;
    if (buf_offset >= this._prefetch_data[index].length) {
      // it's not here
      return null;
    }
    return index;
  },

  /*
    read data out of the prefetch buffer, if possible.  if the data isn't
    in the buffer, return None.  otherwise, behaves like a normal read.
  */
  _read_prefetch : function(size, callback) {
    // while not closed, and haven't fetched past the current position, and haven't reached EOF...

    var offset = this._data_in_prefetch_buffers(this._realpos);
    if (offset != null) {
      this._read_prefetch_finished(size, offset, callback);
      return;
    }
    if (this._prefetch_done || this._closed) {
      this._read_prefetch_finished(size, null, callback);
      return;
    }

    var self = this;
    var read_response_callback = function() {
      self._check_exception();
      self._read_prefetch(size, callback);
    };
    this.sftp._read_response(null, read_response_callback);
  },

  _read_prefetch_finished : function(size, offset, callback) {
    if (offset == null) {
      this._prefetching = false;
      callback(null);
      return;
    }
    var prefetch = this._prefetch_data[offset];
    delete this._prefetch_data[offset];

    var buf_offset = this._realpos - offset;
    if (buf_offset > 0) {
      this._prefetch_data[offset] = prefetch.substring(0, buf_offset);
      prefetch = prefetch.substring(buf_offset);
    }
    if (size < prefetch.length) {
      this._prefetch_data[this._realpos + size] = prefetch.substring(size);
      prefetch = prefetch.substring(0, size);
    }
    callback(prefetch);
  },

  _read : function(size, callback) {
    size = Math.min(size, this.MAX_REQUEST_SIZE);
    if (this._prefetching) {
      this._read_prefetch(size, callback);
      return;
    }
    var self = this;
    var read_callback = function(result, eofError, ioError) {
      if (eofError) {
        callback(null);
        return;
      }
      if (result[0] != self.sftp.CMD_DATA) {
        throw new paramikojs.ssh_exception.SFTPError('Expected data');
      }
      callback(result[1].get_string());
    };
    this.sftp._request(this.sftp.CMD_READ, read_callback, this.handle, new BigInteger(this._realpos.toString(), 10), size);
  },

  _write : function(data, callback, total_data_len) {
    // may write less than requested if it would exceed max packet size
    var chunk = Math.min(data.length, this.MAX_REQUEST_SIZE);
    var req = this.sftp._async_request(null, this.sftp.CMD_WRITE, null, [this.handle, new BigInteger(this._realpos.toString(), 10), data.substring(0, chunk)]);
    if (!this.pipelined || this.sftp.sock.recv_ready()) {
      var self = this;
      var response_callback = function(result) {
        if (result[0] != self.sftp.CMD_STATUS) {
          throw new paramikojs.ssh_exception.SFTPError('Expected status');
        }
        // convert_status already called
        if (total_data_len <= self.MAX_REQUEST_SIZE) {
          callback();
        }
      }
      this.sftp._read_response(req, response_callback);
    }
    return chunk;
  },

  /*
    Set a timeout on read/write operations on the underlying socket or
    ssh L{Channel}.

    @see: L{Channel.settimeout}
    @param timeout: seconds to wait for a pending read/write operation
        before raising C{socket.timeout}, or C{None} for no timeout
    @type timeout: float
  */
  settimeout : function(timeout) {
    this.sftp.sock.settimeout(timeout);
  },

  /*
    Returns the timeout in seconds (as a float) associated with the socket
    or ssh L{Channel} used for this file.

    @see: L{Channel.gettimeout}
    @rtype: float
  */
  gettimeout : function() {
    return this.sftp.sock.gettimeout();
  },

  /*
    Set blocking or non-blocking mode on the underiying socket or ssh
    L{Channel}.

    @see: L{Channel.setblocking}
    @param blocking: 0 to set non-blocking mode; non-0 to set blocking
        mode.
    @type blocking: int
  */
  setblocking : function(blocking) {
    this.sftp.sock.setblocking(blocking);
  },

  seek : function(offset, whence) {
    whence = whence || 0;
    this.flush();
    if (whence == this.SEEK_SET) {
      this._realpos = this._pos = offset;
    } else if (whence == this.SEEK_CUR) {
      this._pos += offset;
      this._realpos = this._pos;
    } else {
      this._realpos = this._pos = this._get_size() + offset;
    }
    this._rbuffer = '';
  },

  /*
    Retrieve information about this file from the remote system.  This is
    exactly like L{SFTP.stat}, except that it operates on an already-open
    file.

    @return: an object containing attributes about this file.
    @rtype: SFTPAttributes
  */
  stat : function(callback) {
    var self = this;
    var stat_callback = function(result, eofError, ioError) {
      if (ioError) {
        callback(ioError);
      } else if (result[0] != self.sftp.CMD_ATTRS) {
        callback(false);
      } else {
        callback(new paramikojs.SFTPAttributes()._from_msg(result[1]));
      }
    };
    this.sftp._request(this.sftp.CMD_FSTAT, stat_callback, this.handle);
  },

  /*
    Change the mode (permissions) of this file.  The permissions are
    unix-style and identical to those used by python's C{os.chmod}
    function.

    @param mode: new permissions
    @type mode: int
  */
  chmod : function(mode) {
    this.sftp._log(DEBUG, 'chmod(' + paramikojs.util.hexify(this.handle) + ', ' + mode + ')');
    var attr = new paramikojs.SFTPAttributes();
    attr.st_mode = mode;
    this.sftp._request(this.sftp.CMD_FSETSTAT, null, this.handle, attr);
  },

  /*
    Change the owner (C{uid}) and group (C{gid}) of this file.  As with
    python's C{os.chown} function, you must pass both arguments, so if you
    only want to change one, use L{stat} first to retrieve the current
    owner and group.

    @param uid: new owner's uid
    @type uid: int
    @param gid: new group id
    @type gid: int
  */
  chown : function(uid, gid) {
    this.sftp._log(DEBUG, 'chown(' + paramikojs.util.hexify(this.handle) + ', ' + uid +', ' + gid + ')');
    var attr = new paramikojs.SFTPAttributes();
    attr.st_uid = uid;
    attr.st_gid = gid;
    this.sftp._request(this.sftp.CMD_FSETSTAT, null, this.handle, attr);
  },

  /*
    Set the access and modified times of this file.  If
    C{times} is C{None}, then the file's access and modified times are set
    to the current time.  Otherwise, C{times} must be a 2-tuple of numbers,
    of the form C{(atime, mtime)}, which is used to set the access and
    modified times, respectively.  This bizarre API is mimicked from python
    for the sake of consistency -- I apologize.

    @param times: C{None} or a tuple of (access time, modified time) in
        standard internet epoch time (seconds since 01 January 1970 GMT)
    @type times: tuple(int)
  */
  utime : function(times) {
    if (!times) {
      times = [new Date(), new Date()];
    }
    this.sftp._log(DEBUG, 'utime(' + paramikojs.util.hexify(this.handle) + ', ' + times + ')');
    var attr = new paramikojs.SFTPAttributes();
    attr.st_atime = times[0];
    attr.st_mtime = times[1];
    this.sftp._request(this.sftp.CMD_FSETSTAT, null, this.handle, attr);
  },

  /*
    Change the size of this file.  This usually extends
    or shrinks the size of the file, just like the C{truncate()} method on
    python file objects.

    @param size: the new size of the file
    @type size: int or long
  */
  truncate : function(size) {
    this.sftp._log(DEBUG, 'truncate(' + paramikojs.util.hexify(this.handle) + ', ' + size + ')');
    var attr = new paramikojs.SFTPAttributes();
    attr.st_size = size;
    this.sftp._request(this.sftp.CMD_FSETSTAT, null, this.handle, attr);
  },

  /*
    Ask the server for a hash of a section of this file.  This can be used
    to verify a successful upload or download, or for various rsync-like
    operations.

    The file is hashed from C{offset}, for C{length} bytes.  If C{length}
    is 0, the remainder of the file is hashed.  Thus, if both C{offset}
    and C{length} are zero, the entire file is hashed.

    Normally, C{block_size} will be 0 (the default), and this method will
    return a byte string representing the requested hash (for example, a
    string of length 16 for MD5, or 20 for SHA-1).  If a non-zero
    C{block_size} is given, each chunk of the file (from C{offset} to
    C{offset + length}) of C{block_size} bytes is computed as a separate
    hash.  The hash results are all concatenated and returned as a single
    string.

    For example, C{check('sha1', 0, 1024, 512)} will return a string of
    length 40.  The first 20 bytes will be the SHA-1 of the first 512 bytes
    of the file, and the last 20 bytes will be the SHA-1 of the next 512
    bytes.

    @param hash_algorithm: the name of the hash algorithm to use (normally
        C{"sha1"} or C{"md5"})
    @type hash_algorithm: str
    @param offset: offset into the file to begin hashing (0 means to start
        from the beginning)
    @type offset: int or long
    @param length: number of bytes to hash (0 means continue to the end of
        the file)
    @type length: int or long
    @param block_size: number of bytes to hash per result (must not be less
        than 256; 0 means to compute only one hash of the entire segment)
    @type block_size: int
    @return: string of bytes representing the hash of each block,
        concatenated together
    @rtype: str

    @note: Many (most?) servers don't support this extension yet.

    @raise IOError: if the server doesn't support the "check-file"
        extension, or possibly doesn't support the hash algorithm
        requested

    @since: 1.4
  */
  check : function(hash_algorithm, offset, length, block_size) {
    offset = offset || 0;
    length = length || 0;
    block_size = block_size || 0;

    var result = this.sftp._request(this.sftp.CMD_EXTENDED, null, 'check-file', this.handle,
                                hash_algorithm, new BigInteger(offset.toString(), 10), new BigInteger(length.toString(), 10), block_size);
    ext = result[1].get_string();
    alg = result[1].get_string();
    data = result[1].get_remainder();
    return data;
  },

  /*
    Turn on/off the pipelining of write operations to this file.  When
    pipelining is on, paramiko won't wait for the server response after
    each write operation.  Instead, they're collected as they come in.
    At the first non-write operation (including L{close}), all remaining
    server responses are collected.  This means that if there was an error
    with one of your later writes, an exception might be thrown from
    within L{close} instead of L{write}.

    By default, files are I{not} pipelined.

    @param pipelined: C{True} if pipelining should be turned on for this
        file; C{False} otherwise
    @type pipelined: bool

    @since: 1.5
  */
  set_pipelined : function(pipelined) {
    pipelined = pipelined == undefined ? true : pipelined;
    this.pipelined = pipelined;
  },

  /*
    Pre-fetch the remaining contents of this file in anticipation of
    future L{read} calls.  If reading the entire file, pre-fetching can
    dramatically improve the download speed by avoiding roundtrip latency.
    The file's contents are incrementally buffered in a background thread.

    The prefetched data is stored in a buffer until read via the L{read}
    method.  Once data has been read, it's removed from the buffer.  The
    data may be read in a random order (using L{seek}); chunks of the
    buffer that haven't been read will continue to be buffered.

    @since: 1.5.1
  */
  prefetch : function(callback) {
    var self = this;
    var stat_callback = function(attr) {
      if (attr instanceof paramikojs.ssh_exception.IOError) {
        throw attr;
      }

      var size = self.size = attr.st_size;
      // queue up async reads for the rest of the file
      var chunks = [];
      var n = self._realpos;
      while (n < size) {
        chunk = Math.min(self.MAX_REQUEST_SIZE, size - n);
        chunks.push([n, chunk]);
        n += chunk;
      }
      if (chunks.length > 0) {
        self._start_prefetch(chunks);
      }

      callback();
    };

    this.stat(stat_callback);
  },

  /*
    Read a set of blocks from the file by (offset, length).  This is more
    efficient than doing a series of L{seek} and L{read} calls, since the
    prefetch machinery is used to retrieve all the requested blocks at
    once.

    @param chunks: a list of (offset, length) tuples indicating which
        sections of the file to read
    @type chunks: list(tuple(long, int))
    @return: a list of blocks read, in the same order as in C{chunks}
    @rtype: list(str)

    @since: 1.5.4
  */
  readv : function(chunks) {
    this.sftp._log(DEBUG, 'readv(' + paramikojs.util.hexify(this.handle) + ', ' + chunks + ')');

    var read_chunks = [];
    for (var x = 0; x < chunks.length; ++x) {
      var offset = chunks[x][0];
      var size = chunks[x][1];
      // don't fetch data that's already in the prefetch buffer
      if (this._data_in_prefetch_buffers(offset) || this._data_in_prefetch_requests(offset, size)) {
        continue;
      }

      // break up anything larger than the max read size
      while (size > 0) {
        var chunk_size = Math.min(size, this.MAX_REQUEST_SIZE);
        read_chunks.push([offset, chunk_size]);
        offset += chunk_size;
        size -= chunk_size;
      }
    }

    this._start_prefetch(read_chunks);
    // now we can just devolve to a bunch of read()s :)
    var results = [];
    for (var x; x < chunks.length; ++x) {
      this.seek(chunks[x][0]);
      results.push(this.read(chunks[x][1]));
    }
  },


  //  internals...


  _get_size : function() {
    return this._size;
    // we avoid making this call to simplify things and create less callbacks
    /*try {
      return this.stat().st_size;
    } catch(ex) {
      return 0;
    }*/
  },

  _start_prefetch : function(chunks) {
    this._prefetching = true;
    this._prefetch_done = false;
    this._prefetch_reads = this._prefetch_reads.concat(chunks);

    this._prefetch_thread(chunks);
  },

  _prefetch_thread : function(chunks) {
    // do these read requests in a temporary thread because there may be
    // a lot of them, so it may block.
    for (var x = 0; x < chunks.length; ++x) {
      var offset = chunks[x][0];
      var length = chunks[x][1];
      this.sftp._async_request(this, this.sftp.CMD_READ, null, [this.handle, new BigInteger(offset.toString(), 10), length]);
    }
  },

  _async_response : function(t, msg) {
    if (t == this.sftp.CMD_STATUS) {
      // save exception and re-raise it on next file operation
      try {
        this.sftp._convert_status(msg);
      } catch(ex) {
        this._saved_exception = ex;
      }
      return;
    }
    if (t != this.sftp.CMD_DATA) {
      throw new paramikojs.ssh_exception.SFTPError('Expected data');
    }
    var data = msg.get_string();
    var prefetch_read = this._prefetch_reads.shift();
    this._prefetch_data[prefetch_read[0]] = data;
    if (this._prefetch_reads.length == 0) {
      this._prefetch_done = true;
    }
  },

  // if there's a saved exception, raise & clear it
  _check_exception : function() {
    if (this._saved_exception) {
      var x = this._saved_exception;
      this._saved_exception = null;
      throw x;
    }
  }
};
