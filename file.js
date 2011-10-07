/*
  Reusable base class to implement python-style file buffering around a
  simpler stream.
*/
paramikojs.BufferedFile = function() {
  this.newlines = null;
  this._flags = 0;
  this._bufsize = this._DEFAULT_BUFSIZE;
  this._wbuffer = "";
  this._rbuffer = "";
  this._at_trailing_cr = false;
  this._closed = false;
  // pos - position within the file, according to the user
  // realpos - position according the OS
  // (these may be different because we buffer for line reading)
  this._pos = this._realpos = 0;
  // size only matters for seekable files
  this._size = 0;
}

paramikojs.BufferedFile.prototype = {
  _DEFAULT_BUFSIZE : 8192,

  SEEK_SET : 0,
  SEEK_CUR : 1,
  SEEK_END : 2,

  FLAG_READ : 0x1,
  FLAG_WRITE : 0x2,
  FLAG_APPEND : 0x4,
  FLAG_BINARY : 0x10,
  FLAG_BUFFERED : 0x20,
  FLAG_LINE_BUFFERED : 0x40,
  FLAG_UNIVERSAL_NEWLINE : 0x80,

  /*
    Close the file.  Future read and write operations will fail.
  */
  __close : function() {
    this.flush();
    this._closed = true;
  },

  close : function() {
    this.__close();
  },

  /*
    Write out any data in the write buffer.  This may do nothing if write
    buffering is not turned on.
  */
  flush : function(callback) {
    this._write_all(this._wbuffer, callback);
    this._wbuffer = "";
    return;
  },

  /*
    Returns the next line from the input, or raises L{StopIteration} when
    EOF is hit.  Unlike python file objects, it's okay to mix calls to
    C{next} and L{readline}.

    @raise StopIteration: when the end of the file is reached.

    @return: a line read from the file.
    @rtype: str
  */
  next : function() {
    var line = this.readline();
    if (!line) {
      throw StopIteration;
    }
    return line;
  },

  /*
    Read at most C{size} bytes from the file (less if we hit the end of the
    file first).  If the C{size} argument is negative or omitted, read all
    the remaining data in the file.

    @param size: maximum number of bytes to read
    @type size: int
    @return: data read from the file, or an empty string if EOF was
        encountered immediately
    @rtype: str
  */
  read : function(size, callback) {
    if (this._closed) {
      throw new paramikojs.ssh_exception.IOError('File is closed');
    }
    if (!(this._flags & this.FLAG_READ)) {
      throw new paramikojs.ssh_exception.IOError('File is not open for reading');
    }
    var result;
    if (!size || size < 0) {
      // go for broke
      result = this._rbuffer;
      this._rbuffer = '';
      this._pos += result.length;
      this.read_all(callback, result);
      return;
    }
    if (size <= this._rbuffer.length) {
      result = this._rbuffer.substring(0, size);
      this._rbuffer = this._rbuffer.substring(size);
      this._pos += result.length;
      callback(result);
      return;
    }
    this.read_some(callback, size);
  },

  read_all : function(callback, result) {
    var self = this;
    var read_callback = function(new_data, eofError, ioError) {
      if (eofError) {
        new_data = null;
      }

      if (!new_data || new_data.length == 0) {
        callback(result);
        return;
      }
      result += new_data;
      self._realpos += new_data.length;
      self._pos += new_data.length;
      self.read_all(callback, result);
    };
    this._read(this._DEFAULT_BUFSIZE, read_callback);
  },

  read_some : function(callback, size) {
    var self = this;
    var read_callback = function(new_data, eofError, ioError) {
      if (eofError) {
        new_data = null;
      }

      if (!new_data || new_data.length == 0) {
        self.read_finish(callback, size);
        return;
      }

      self._rbuffer += new_data;
      self._realpos += new_data.length;

      self.read_some(callback, size);
    };

    if (this._rbuffer.length < size) {
      var read_size = size - this._rbuffer.length;
      if (this._flags & this.FLAG_BUFFERED) {
        read_size = Math.max(this._bufsize, read_size);
      }
      this._read(read_size, read_callback);
      return;
    }
    this.read_finish(callback, size);
  },

  read_finish : function(callback, size) {
    var result = this._rbuffer.substring(0, size);
    this._rbuffer = this._rbuffer.substring(size);
    this._pos += result.length;
    callback(result);
  },

  /*
    Read one entire line from the file.  A trailing newline character is
    kept in the string (but may be absent when a file ends with an
    incomplete line).  If the size argument is present and non-negative, it
    is a maximum byte count (including the trailing newline) and an
    incomplete line may be returned.  An empty string is returned only when
    EOF is encountered immediately.

    @note: Unlike stdio's C{fgets()}, the returned string contains null
    characters (C{'\\0'}) if they occurred in the input.

    @param size: maximum length of returned string.
    @type size: int
    @return: next line of the file, or an empty string if the end of the
        file has been reached.
    @rtype: str
  */
  readline : function(size) {
    // todo transcode if necessary
    /*
    # it's almost silly how complex this function is.
    if self._closed:
        raise IOError('File is closed')
    if not (self._flags & self.FLAG_READ):
        raise IOError('File not open for reading')
    line = self._rbuffer
    while True:
        if self._at_trailing_cr and (self._flags & self.FLAG_UNIVERSAL_NEWLINE) and (len(line) > 0):
            # edge case: the newline may be '\r\n' and we may have read
            # only the first '\r' last time.
            if line[0] == '\n':
                line = line[1:]
                self._record_newline('\r\n')
            else:
                self._record_newline('\r')
            self._at_trailing_cr = False
        # check size before looking for a linefeed, in case we already have
        # enough.
        if (size is not None) and (size >= 0):
            if len(line) >= size:
                # truncate line and return
                self._rbuffer = line[size:]
                line = line[:size]
                self._pos += len(line)
                return line
            n = size - len(line)
        else:
            n = self._bufsize
        if ('\n' in line) or ((self._flags & self.FLAG_UNIVERSAL_NEWLINE) and ('\r' in line)):
            break
        try:
            new_data = self._read(n)
        except EOFError:
            new_data = None
        if (new_data is None) or (len(new_data) == 0):
            self._rbuffer = ''
            self._pos += len(line)
            return line
        line += new_data
        self._realpos += len(new_data)
    # find the newline
    pos = line.find('\n')
    if self._flags & self.FLAG_UNIVERSAL_NEWLINE:
        rpos = line.find('\r')
        if (rpos >= 0) and ((rpos < pos) or (pos < 0)):
            pos = rpos
    xpos = pos + 1
    if (line[pos] == '\r') and (xpos < len(line)) and (line[xpos] == '\n'):
        xpos += 1
    self._rbuffer = line[xpos:]
    lf = line[pos:xpos]
    line = line[:pos] + '\n'
    if (len(self._rbuffer) == 0) and (lf == '\r'):
        # we could read the line up to a '\r' and there could still be a
        # '\n' following that we read next time.  note that and eat it.
        self._at_trailing_cr = True
    else:
        self._record_newline(lf)
    self._pos += len(line)
    return line
    */
  },

  /*
    Read all remaining lines using L{readline} and return them as a list.
    If the optional C{sizehint} argument is present, instead of reading up
    to EOF, whole lines totalling approximately sizehint bytes (possibly
    after rounding up to an internal buffer size) are read.

    @param sizehint: desired maximum number of bytes to read.
    @type sizehint: int
    @return: list of lines read from the file.
    @rtype: list
  */
  readlines : function(sizehint) {
    // todo transcode if necessary
    /*
    lines = []
    bytes = 0
    while True:
        line = self.readline()
        if len(line) == 0:
            break
        lines.append(line)
        bytes += len(line)
        if (sizehint is not None) and (bytes >= sizehint):
            break
    return lines
    */
  },

  /*
    Set the file's current position, like stdio's C{fseek}.  Not all file
    objects support seeking.

    @note: If a file is opened in append mode (C{'a'} or C{'a+'}), any seek
        operations will be undone at the next write (as the file position
        will move back to the end of the file).
    
    @param offset: position to move to within the file, relative to
        C{whence}.
    @type offset: int
    @param whence: type of movement: 0 = absolute; 1 = relative to the
        current position; 2 = relative to the end of the file.
    @type whence: int

    @raise IOError: if the file doesn't support random access.
  */
  seek : function(offset, whence) {
    throw new paramikojs.ssh_exception.IOError('File does not support seeking.');
  },

  /*
    Return the file's current position.  This may not be accurate or
    useful if the underlying file doesn't support random access, or was
    opened in append mode.

    @return: file position (in bytes).
    @rtype: int
  */
  tell : function() {
    return this._pos;
  },

  /*
    Write data to the file.  If write buffering is on (C{bufsize} was
    specified and non-zero), some or all of the data may not actually be
    written yet.  (Use L{flush} or L{close} to force buffered data to be
    written out.)

    @param data: data to write.
    @type data: str
  */
  write : function(data, callback) {
    if (this._closed) {
      throw new paramikojs.ssh_exception.IOError('File is closed');
    }
    if (!(this._flags & this.FLAG_WRITE)) {
      throw new paramikojs.ssh_exception.IOError('File not open for writing');
    }
    if (!(this._flags & this.FLAG_BUFFERED)) {
      this._write_all(data, callback);
      return;
    }
    this._wbuffer += data;
    if (this._flags & this.FLAG_LINE_BUFFERED) {
      // only scan the new data for linefeed, to avoid wasting time.
      var last_newline_pos = data.lastIndexOf('\n');
      if (last_newline_pos >= 0) {
        var wbuf = this._wbuffer;
        last_newline_pos += wbuf.length - data.length;
        this._write_all(wbuf.substring(0, last_newline_pos + 1), callback);
        this._wbuffer = "";
        this._wbuffer += wbuf.substring(last_newline_pos + 1);
      }
      return;
    }
    // even if we're line buffering, if the buffer has grown past the
    // buffer size, force a flush.
    if (this._wbuffer.length >= this._bufsize) {
      this.flush(callback);
    }
    return;
  },

  /*
    Write a sequence of strings to the file.  The sequence can be any
    iterable object producing strings, typically a list of strings.  (The
    name is intended to match L{readlines}; C{writelines} does not add line
    separators.)

    @param sequence: an iterable sequence of strings.
    @type sequence: sequence
  */
  writelines : function(sequence) {
    for (var x = 0; x < sequence.length; ++x) {
      this.write(sequence[x]);
    }
    return;
  },

  /*
    Identical to C{iter(f)}.  This is a deprecated file interface that
    predates python iterator support.

    @return: an iterator.
    @rtype: iterator
  */
  xreadlines : function() {
    return this;
  },


  //  overrides...


  /*
    I{(subclass override)}
    Read data from the stream.  Return C{None} or raise C{EOFError} to
    indicate EOF.
  */
  _read : function(size) {
    throw new paramikojs.ssh_exception.EOFError();
  },

  /*
    I{(subclass override)}
    Write data into the stream.
  */
  _write : function(data) {
    throw new paramikojs.ssh_exception.IOError('write not implemented');
  },

  /*
    I{(subclass override)}
    Return the size of the file.  This is called from within L{_set_mode}
    if the file is opened in append mode, so the file position can be
    tracked and L{seek} and L{tell} will work correctly.  If the file is
    a stream that can't be randomly accessed, you don't need to override
    this method,
  */
  _get_size : function() {
    return 0;
  },


  //  internals...


  /*
    Subclasses call this method to initialize the BufferedFile.
  */
  _set_mode : function(mode, bufsize) {
    mode = mode || 'r';
    bufsize = bufsize || -1;

    // set bufsize in any event, because it's used for readline().
    this._bufsize = this._DEFAULT_BUFSIZE;
    if (bufsize < 0) {
      // do no buffering by default, because otherwise writes will get
      // buffered in a way that will probably confuse people.
      bufsize = 0;
    }
    if (bufsize == 1) {
      // apparently, line buffering only affects writes.  reads are only
      // buffered if you call readline (directly or indirectly: iterating
      // over a file will indirectly call readline).
      this._flags |= this.FLAG_BUFFERED | this.FLAG_LINE_BUFFERED;
    } else if (bufsize > 1) {
      this._bufsize = bufsize;
      this._flags |= this.FLAG_BUFFERED
      this._flags &= ~this.FLAG_LINE_BUFFERED;
    } else if (bufsize == 0) {
      // unbuffered
      this._flags &= ~(this.FLAG_BUFFERED | this.FLAG_LINE_BUFFERED);
    }

    if (mode.indexOf('r') != -1 || mode.indexOf('+') != -1) {
      this._flags |= this.FLAG_READ;
    }
    if (mode.indexOf('w') != -1 || mode.indexOf('+') != -1) {
      this._flags |= this.FLAG_WRITE;
    }
    if (mode.indexOf('a') != -1) {
      this._flags |= this.FLAG_WRITE | this.FLAG_APPEND;
      this._size = this._get_size();
      this._pos = this._realpos = this._size;
    }
    if (mode.indexOf('b') != -1) {
      this._flags |= this.FLAG_BINARY;
    }
    if (mode.indexOf('U') != -1) {
      this._flags |= this.FLAG_UNIVERSAL_NEWLINE;
      // built-in file objects have this attribute to store which kinds of
      // line terminations they've seen:
      // <http://www.python.org/doc/current/lib/built-in-funcs.html>
      this.newlines = null;
    }
  },

  _write_all : function(data, callback) {
    // the underlying stream may be something that does partial writes (like
    // a socket).
    while (data.length > 0) {
      var count = this._write(data, callback, data.length);
      data = data.substring(count);
      if (this._flags & this.FLAG_APPEND) {
        this._size += count;
        this._pos = this._realpos = this._size;
      } else {
        this._pos += count;
        this._realpos += count;
      }
    }
    /*if (callback) {
      callback();
    }*/
    return null;
  },

  _record_newline : function(newline) {
    // todo transcode if necessary
    /*
    # silliness about tracking what kinds of newlines we've seen.
    # i don't understand why it can be None, a string, or a tuple, instead
    # of just always being a tuple, but we'll emulate that behavior anyway.
    if not (self._flags & self.FLAG_UNIVERSAL_NEWLINE):
        return
    if self.newlines is None:
        self.newlines = newline
    elif (type(self.newlines) is str) and (self.newlines != newline):
        self.newlines = (self.newlines, newline)
    elif newline not in self.newlines:
        self.newlines += (newline,)
    */
  }
};
