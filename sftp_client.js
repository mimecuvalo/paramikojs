/*
  SFTP client object.  C{SFTPClient} is used to open an sftp session across
  an open ssh L{Transport} and do remote file operations.
*/

paramikojs.SFTPClient = function(sock, transport, callback) {
  /*
    Create an SFTP client from an existing L{Channel}.  The channel
    should already have requested the C{"sftp"} subsystem.

    An alternate way to create an SFTP client context is by using
    L{from_transport}.

    @param sock: an open L{Channel} using the C{"sftp"} subsystem
    @type sock: L{Channel}

    @raise SSHException: if there's an exception while negotiating
        sftp
  */

	inherit(this, new paramikojs.BaseSFTP());

  this.sock = sock;
  this.transport = transport;
  this.ultra_debug = false;
  this.request_number = 1;
  // lock for request_number
  this._cwd = null;
  // request # -> SFTPFile
  this._expecting = {};
  this._deferred_packet = null;
  this.logger = paramikojs.util.get_logger();

  var self = this;
  var send_version_callback = function(server_version) {
    self._log(INFO, 'Opened sftp connection (server version ' + server_version + ')');
    callback(self);
  }
  this._send_version(send_version_callback);
}

/*
  Create an SFTP client channel from an open L{Transport}.

  @param t: an open L{Transport} which is already authenticated
  @type t: L{Transport}
  @return: a new L{SFTPClient} object, referring to an sftp session
      (channel) across the transport
  @rtype: L{SFTPClient}
*/
paramikojs.SFTPClient.from_transport = function(t, callback) {
  var on_success = function(chan) {
    chan.invoke_subsystem('sftp');
    var client = new paramikojs.SFTPClient(chan, t, callback);
  }
  t.open_session(on_success);
};

paramikojs.SFTPClient.prototype = {
  _log : function(level, msg) {
    this.logger.log(level, msg);
  },

  /*
    Close the SFTP session and its underlying channel.

    @since: 1.4
  */
  close : function() {
    this._log(INFO, 'sftp session closed.');
    this.sock.close();
  },

  /*
    Return the underlying L{Channel} object for this SFTP session.  This
    might be useful for doing things like setting a timeout on the channel.

    @return: the SSH channel
    @rtype: L{Channel}

    @since: 1.7.1
  */
  get_channel : function() {
    return this.sock;
  },

  /*
    Return a list containing the names of the entries in the given C{path}.
    The list is in arbitrary order.  It does not include the special
    entries C{'.'} and C{'..'} even if they are present in the folder.
    This method is meant to mirror C{os.listdir} as closely as possible.
    For a list of full L{SFTPAttributes} objects, see L{listdir_attr}.

    @param path: path to list (defaults to C{'.'})
    @type path: str
    @return: list of filenames
    @rtype: list of str
  */
  listdir : function(path, callback) {
    path = path || '.';

    var listdir_callback = function(results) {
      callback(results);
    };

    this.listdir_attr(path, listdir_callback);
  },

  /*
    Return a list containing L{SFTPAttributes} objects corresponding to
    files in the given C{path}.  The list is in arbitrary order.  It does
    not include the special entries C{'.'} and C{'..'} even if they are
    present in the folder.

    The returned L{SFTPAttributes} objects will each have an additional
    field: C{longname}, which may contain a formatted string of the file's
    attributes, in unix format.  The content of this string will probably
    depend on the SFTP server implementation.

    @param path: path to list (defaults to C{'.'})
    @type path: str
    @return: list of attributes
    @rtype: list of L{SFTPAttributes}

    @since: 1.2
  */
  listdir_attr : function(path, listdir_callback) {
    path = path || '.';
    path = this._adjust_cwd(path);
    this._log(DEBUG, 'listdir(' + path + ')');

    var self = this;
    var opendir_callback = function(result, eofError, ioError) {
      if (ioError) {
        listdir_callback(ioError);
        return;
      }
      if (!result || result[0] != self.CMD_HANDLE) {
        listdir_callback(new paramikojs.ssh_exception.SFTPError('Expected handle'));
        return;
      }

      var handle = result[1].get_string();
      self.listdir_attr_callback(handle, listdir_callback);
    };

    this._request(this.CMD_OPENDIR, opendir_callback, path);
  },

  listdir_attr_callback : function(handle, listdir_callback, filelist) {
    filelist = filelist || [];

    var self = this;
    var read_callback = function(result, eofError, ioError) {
      if (ioError) {
        listdir_callback(ioError);
        return;
      }
      if (eofError) {
        self.listdir_attr_close_callback(handle, listdir_callback, filelist);
        return;
      }
      if (!result || result[0] != self.CMD_NAME) {
        listdir_callback(new paramikojs.ssh_exception.SFTPError('Expected name response'));
        return;
      }
      var count = result[1].get_int();
      for (var x = 0; x < count; ++x) {
        var filename = result[1].get_string();
        try {
          filename = self.transport.toUTF8.convertStringToUTF8(filename, "UTF-8", 1);
        } catch(ex) {
          self._log(DEBUG, ex);
        }
        var longname = result[1].get_string();
        try {
          longname = self.transport.toUTF8.convertStringToUTF8(longname, "UTF-8", 1);
        } catch(ex) {
          self._log(DEBUG, ex);
        }
        var attr = new paramikojs.SFTPAttributes()._from_msg(result[1], filename, longname);
        if (filename != '.' && filename != '..') {
          filelist.push(attr);
        }
      }

      self.listdir_attr_callback(handle, listdir_callback, filelist);
    };
    this._request(this.CMD_READDIR, read_callback, handle);
  },

  listdir_attr_close_callback : function(handle, listdir_callback, filelist) {
    var self = this;
    var close_callback = function(result) {
      self.listdir_check_symlinks(listdir_callback, filelist);
    };
    this._request(this.CMD_CLOSE, close_callback, handle);
  },

  listdir_check_symlinks : function(listdir_callback, filelist) {
    var files_to_check = [];
    for (var x = 0; x < filelist.length; ++x) {
      if (filelist[x].longname.charAt(0) == 'l') {
        var index = x;
        var filename = filelist[x].filename;
        files_to_check.push({ 'index': index, 'filename': filename });
      }
    }

    if (files_to_check.length) {
      for (var x = 0; x < files_to_check.length; ++x) {
        var index = files_to_check[x].index;
        var last = x == files_to_check.length - 1;
        var symlink_callback = this.listdir_check_symlinks_helper(listdir_callback, filelist, index, last);
        this.readlink(files_to_check[x].filename, symlink_callback);
      }
    } else {
      listdir_callback(filelist);
    }
  },

  listdir_check_symlinks_helper : function(listdir_callback, filelist, index, last) {
    return function(result) {
      filelist[index].longname += ' -> ' + result;

      if (last) {
        listdir_callback(filelist);
      }
    };
  },

  /*
    Open a file on the remote server.  The arguments are the same as for
    python's built-in C{file} (aka C{open}).  A file-like object is
    returned, which closely mimics the behavior of a normal python file
    object.

    The mode indicates how the file is to be opened: C{'r'} for reading,
    C{'w'} for writing (truncating an existing file), C{'a'} for appending,
    C{'r+'} for reading/writing, C{'w+'} for reading/writing (truncating an
    existing file), C{'a+'} for reading/appending.  The python C{'b'} flag
    is ignored, since SSH treats all files as binary.  The C{'U'} flag is
    supported in a compatible way.

    Since 1.5.2, an C{'x'} flag indicates that the operation should only
    succeed if the file was created and did not previously exist.  This has
    no direct mapping to python's file flags, but is commonly known as the
    C{O_EXCL} flag in posix.

    The file will be buffered in standard python style by default, but
    can be altered with the C{bufsize} parameter.  C{0} turns off
    buffering, C{1} uses line buffering, and any number greater than 1
    (C{>1}) uses that specific buffer size.

    @param filename: name of the file to open
    @type filename: str
    @param mode: mode (python-style) to open in
    @type mode: str
    @param bufsize: desired buffering (-1 = default buffer size)
    @type bufsize: int
    @return: a file object representing the open file
    @rtype: SFTPFile

    @raise IOError: if the file could not be opened.
  */
  open : function(filename, mode, bufsize, open_callback, current_size) {
    mode = mode || 'r';
    bufsize = bufsize || -1;
    current_size = current_size || 0;
    filename = this._adjust_cwd(filename);
    this._log(DEBUG, 'open(' + filename + ', ' + mode + ')');
    var imode = 0;
    if (mode.indexOf('r') != -1 || mode.indexOf('+') != -1) {
      imode |= this.SFTP_FLAG_READ;
    }
    if (mode.indexOf('w') != -1 || mode.indexOf('+') != -1 || mode.indexOf('a') != -1) {
      imode |= this.SFTP_FLAG_WRITE;
    }
    if (mode.indexOf('w') != -1) {
      imode |= this.SFTP_FLAG_CREATE | this.SFTP_FLAG_TRUNC;
    }
    if (mode.indexOf('a') != -1) {
      imode |= this.SFTP_FLAG_CREATE | this.SFTP_FLAG_APPEND;
    }
    if (mode.indexOf('x') != -1) {
      imode |= this.SFTP_FLAG_CREATE | this.SFTP_FLAG_EXCL;
    }
    var attrblock = new paramikojs.SFTPAttributes();

    var self = this;
    var cmd_callback = function(result) {
      if (!result || result[0] != self.CMD_HANDLE) {
        open_callback(new paramikojs.ssh_exception.SFTPError('Expected handle'));
        return;
      }
      var handle = result[1].get_string();
      self._log(DEBUG, 'open(' + filename + ', ' + mode + ') -> ' + paramikojs.util.hexify(handle));
      open_callback(new paramikojs.SFTPFile(self, handle, mode, bufsize, current_size));
    };
    this._request(this.CMD_OPEN, cmd_callback, filename, imode, attrblock);
  },

  /*
    Remove the file at the given path.  This only works on files; for
    removing folders (directories), use L{rmdir}.

    @param path: path (absolute or relative) of the file to remove
    @type path: str

    @raise IOError: if the path refers to a folder (directory)
  */
  remove : function(path, callback) {
    path = this._adjust_cwd(path);
    this._log(DEBUG, 'remove(' + path + ')');

    var self = this;
    var rm_callback = function(result, eofError, ioError) {
      if (ioError) {
        callback(ioError);
      } else {
        callback(true);
      }
    };
    this._request(this.CMD_REMOVE, rm_callback, path);
  },

  /*
    Rename a file or folder from C{oldpath} to C{newpath}.

    @param oldpath: existing name of the file or folder
    @type oldpath: str
    @param newpath: new name for the file or folder
    @type newpath: str

    @raise IOError: if C{newpath} is a folder, or something else goes
        wrong
  */
  rename : function(oldpath, newpath, callback) {
    oldpath = this._adjust_cwd(oldpath);
    newpath = this._adjust_cwd(newpath);
    this._log(DEBUG, 'rename(' + oldpath + ', ' + newpath + ')');

    var self = this;
    var mv_callback = function(result) {
      callback(result);
    };
    this._request(this.CMD_RENAME, mv_callback, oldpath, newpath);
  },

  /*
    Create a folder (directory) named C{path} with numeric mode C{mode}.
    The default mode is 0777 (octal).  On some systems, mode is ignored.
    Where it is used, the current umask value is first masked out.

    @param path: name of the folder to create
    @type path: str
    @param mode: permissions (posix-style) for the newly-created folder
    @type mode: int
  */
  mkdir : function(path, mode, callback) {
    mode = mode || 0777;
    path = this._adjust_cwd(path);
    this._log(DEBUG, 'mkdir(' + path + ', ' + mode + ')');
    var attr = new paramikojs.SFTPAttributes();
    attr.st_mode = mode;

    var self = this;
    var mkdir_callback = function(result, eofError, ioError) {
      if (ioError) {
        callback(ioError);
      } else {
        callback(true);
      }
    };

    this._request(this.CMD_MKDIR, mkdir_callback, path, attr);
  },

  /*
    Remove the folder named C{path}.

    @param path: name of the folder to remove
    @type path: str
  */
  rmdir : function(path, callback) {
    path = this._adjust_cwd(path);
    this._log(DEBUG, 'rmdir(' + path +')');

    var self = this;
    var rmdir_callback = function(result, eofError, ioError) {
      if (ioError) {
        callback(ioError);
      } else {
        callback(true);
      }
    };
    this._request(this.CMD_RMDIR, rmdir_callback, path);
  },

  /*
    Retrieve information about a file on the remote system.  The return
    value is an object whose attributes correspond to the attributes of
    python's C{stat} structure as returned by C{os.stat}, except that it
    contains fewer fields.  An SFTP server may return as much or as little
    info as it wants, so the results may vary from server to server.

    Unlike a python C{stat} object, the result may not be accessed as a
    tuple.  This is mostly due to the author's slack factor.

    The fields supported are: C{st_mode}, C{st_size}, C{st_uid}, C{st_gid},
    C{st_atime}, and C{st_mtime}.

    @param path: the filename to stat
    @type path: str
    @return: an object containing attributes about the given file
    @rtype: SFTPAttributes
  */
  stat : function(path, callback) {
    path = this._adjust_cwd(path);
    this._log(DEBUG, 'stat(' + path + ')');

    var self = this;
    var stat_callback = function(result, eofError, ioError) {
      if (ioError) {
        callback(ioError);
      } else if (result[0] != self.CMD_ATTRS) {
        callback(false);
      } else {
        callback(new paramikojs.SFTPAttributes()._from_msg(result[1]));
      }
    };
    this._request(this.CMD_STAT, stat_callback, path);
  },

  /*
    Retrieve information about a file on the remote system, without
    following symbolic links (shortcuts).  This otherwise behaves exactly
    the same as L{stat}.

    @param path: the filename to stat
    @type path: str
    @return: an object containing attributes about the given file
    @rtype: SFTPAttributes
  */
  lstat : function(path, callback) {
    path = this._adjust_cwd(path);
    this._log(DEBUG, 'lstat(' + path + ')');

    var self = this;
    var lstat_callback = function(result, eofError, ioError) {
      if (ioError) {
        callback(ioError);
      } else if (result[0] != self.CMD_ATTRS) {
        callback(false);
      } else {
        callback(new paramikojs.SFTPAttributes()._from_msg(result[1]));
      }
    };
    this._request(this.CMD_LSTAT, lstat_callback, path);
  },

  /*
    Create a symbolic link (shortcut) of the C{source} path at
    C{destination}.

    @param source: path of the original file
    @type source: str
    @param dest: path of the newly created symlink
    @type dest: str
  */
  symlink : function(source, dest, callback) {
    dest = this._adjust_cwd(dest);
    this._log(DEBUG, 'symlink(' + source + ', ' + dest + ')');
    source = this.transport.fromUTF8.ConvertFromUnicode(source) + this.transport.fromUTF8.Finish();

    var self = this;
    var symlink_callback = function(result, eofError, ioError) {
      if (ioError) {
        callback(ioError);
      } else {
        callback(true);
      }
    };

    this._request(this.CMD_SYMLINK, symlink_callback, source, dest);
  },

  /*
    Change the mode (permissions) of a file.  The permissions are
    unix-style and identical to those used by python's C{os.chmod}
    function.

    @param path: path of the file to change the permissions of
    @type path: str
    @param mode: new permissions
    @type mode: int
  */
  chmod : function(path, mode, callback) {
    path = this._adjust_cwd(path);
    this._log(DEBUG, 'chmod(' + path +', ' + mode + ')');
    var attr = new paramikojs.SFTPAttributes();
    attr.st_mode = mode;

    var self = this;
    var chmod_callback = function(result, eofError, ioError) {
      if (ioError) {
        callback(ioError);
      } else {
        callback(true);
      }
    };
    this._request(this.CMD_SETSTAT, chmod_callback, path, attr);
  },

  /*
    Change the owner (C{uid}) and group (C{gid}) of a file.  As with
    python's C{os.chown} function, you must pass both arguments, so if you
    only want to change one, use L{stat} first to retrieve the current
    owner and group.

    @param path: path of the file to change the owner and group of
    @type path: str
    @param uid: new owner's uid
    @type uid: int
    @param gid: new group id
    @type gid: int
  */
  chown : function(path, uid, gid) {
    path = this._adjust_cwd(path);
    this._log(DEBUG, 'chown(' + path + ', ' + uid + ', ' + gid + ')');
    var attr = new paramikojs.SFTPAttributes();
    attr.st_uid = uid;
    attr.st_gid = gid;
    this._request(this.CMD_SETSTAT, path, attr);
  },

  /*
    Set the access and modified times of the file specified by C{path}.  If
    C{times} is C{None}, then the file's access and modified times are set
    to the current time.  Otherwise, C{times} must be a 2-tuple of numbers,
    of the form C{(atime, mtime)}, which is used to set the access and
    modified times, respectively.  This bizarre API is mimicked from python
    for the sake of consistency -- I apologize.

    @param path: path of the file to modify
    @type path: str
    @param times: C{None} or a tuple of (access time, modified time) in
        standard internet epoch time (seconds since 01 January 1970 GMT)
    @type times: tuple(int)
  */
  utime : function(path, times, callback) {
    path = this._adjust_cwd(path);
    if (!times) {
      times = [new Date(), new Date()];
    }
    this._log(DEBUG, 'utime(' + path + ', ' + times + ')');
    var attr = new paramikojs.SFTPAttributes();
    attr.st_atime = times[0];
    attr.st_mtime = times[1];

    var self = this;
    var utime_callback = function(result, eofError, ioError) {
      if (ioError) {
        callback(ioError);
      } else {
        callback(true);
      }
    };
    this._request(this.CMD_SETSTAT, utime_callback, path, attr);
  },

  /*
    Change the size of the file specified by C{path}.  This usually extends
    or shrinks the size of the file, just like the C{truncate()} method on
    python file objects.

    @param path: path of the file to modify
    @type path: str
    @param size: the new size of the file
    @type size: int or long
  */
  truncate : function(path, size) {
    path = this._adjust_cwd(path);
    this._log(DEBUG, 'truncate(' + path + ', ' + size + ')');
    var attr = new paramikojs.SFTPAttributes();
    attr.st_size = size;
    this._request(this.CMD_SETSTAT, path, attr);
  },

  /*
    Return the target of a symbolic link (shortcut).  You can use
    L{symlink} to create these.  The result may be either an absolute or
    relative pathname.

    @param path: path of the symbolic link file
    @type path: str
    @return: target path
    @rtype: str
  */
  readlink : function(path, callback) {    
    path = this._adjust_cwd(path);
    this._log(DEBUG, 'readlink(' + path + ')');

    var self = this;
    var readlink_callback = function(result) {
      if (!result || result[0] != self.CMD_NAME) {
        callback(new paramikojs.ssh_exception.SFTPError('Expected name response'));
        return;
      }
      var count = result[1].get_int();
      if (count != 1) {
        callback(new paramikojs.ssh_exception.SFTPError('Readlink returned ' + count + ' results'));
        return;
      }
      var path = result[1].get_string();
      try {
        path = self.transport.toUTF8.convertStringToUTF8(path, "UTF-8", 1);
      } catch(ex) {
        self._log(DEBUG, ex);
      }
      callback(path);
    };

    this._request(this.CMD_READLINK, readlink_callback, path);
  },

  /*
    Return the normalized path (on the server) of a given path.  This
    can be used to quickly resolve symbolic links or determine what the
    server is considering to be the "current folder" (by passing C{'.'}
    as C{path}).

    @param path: path to be normalized
    @type path: str
    @return: normalized form of the given path
    @rtype: str

    @raise IOError: if the path can't be resolved on the server
  */
  normalize : function(path, callback) {
    path = this._adjust_cwd(path);
    this._log(DEBUG, 'normalize(' + path + ')');

    var self = this;
    var normalize_callback = function(result) {
      if (!result || result[0] != self.CMD_NAME) {
        callback(new paramikojs.ssh_exception.SFTPError('Expected name response'));
        return;
      }
      var count = result[1].get_int();
      if (count != 1) {
        callback(new paramikojs.ssh_exception.SFTPError('Realpath returned ' + count + ' results'));
        return;
      }
      var path = result[1].get_string();
      try {
        path = self.transport.toUTF8.convertStringToUTF8(path, "UTF-8", 1);
      } catch(ex) {
        self._log(DEBUG, ex);
      }
      callback(path);
    };

    this._request(this.CMD_REALPATH, normalize_callback, path);
  },

  /*
    Change the "current directory" of this SFTP session.  Since SFTP
    doesn't really have the concept of a current working directory, this
    is emulated by paramiko.  Once you use this method to set a working
    directory, all operations on this SFTPClient object will be relative
    to that path. You can pass in C{None} to stop using a current working
    directory.

    @param path: new current working directory
    @type path: str

    @raise IOError: if the requested path doesn't exist on the server

    @since: 1.4
  */
  chdir : function(path, callback) {
    if (!path) {
      this._cwd = null;
      return;
    }

    var self = this;
    var stat_callback = function(attr) {
      if (attr instanceof paramikojs.ssh_exception.IOError || attr instanceof paramikojs.ssh_exception.SFTPError) {
        callback(attr);
      } else if (!attr || (attr.st_mode & 0170000) != 16384) {    // stat.S_ISDIR : S_IFMT(mode) == stat.S_IFDIR
        callback(false);
      } else {
        self.chdir_callback(path, callback);
      }
    };
    this.stat(path, stat_callback);
  },

  chdir_callback : function(path, callback) {
    var self = this;
    var normalize_callback = function(path) {
      self._cwd = path;
      callback(true);
    };
    this.normalize(path, normalize_callback);
  },

  /*
    Return the "current working directory" for this SFTP session, as
    emulated by paramiko.  If no directory has been set with L{chdir},
    this method will return C{None}.

    @return: the current working directory on the server, or C{None}
    @rtype: str

    @since: 1.4
  */
  getcwd : function() {
    return this._cwd;
  },

  /*
    Copy a local file (C{localpath}) to the SFTP server as C{remotepath}.
    Any exception raised by operations will be passed through.  This
    method is primarily provided as a convenience.

    The SFTP operations use pipelining for speed.

    @param localpath: the local file to copy
    @type localpath: str
    @param remotepath: the destination path on the SFTP server
    @type remotepath: str
    @param callback: optional callback function that accepts the bytes
        transferred so far and the total bytes to be transferred
        (since 1.7.4)
    @type callback: function(int, int)
    @param confirm: whether to do a stat() on the file afterwards to
        confirm the file size (since 1.7.7)
    @type confirm: bool

    @return: an object containing attributes about the given file
        (since 1.7.4)
    @rtype: SFTPAttributes

    @since: 1.4
  */
  put : function(localpath, remotepath, remoteSize, callback, confirm, progress_callback) {
    var fl;
    var fileInstream;
    var dataInstream;

    try {
      fl = localFile.init(localpath);
      remoteSize = remoteSize == -1 ? 0 : remoteSize;
      fileInstream = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance();
      fileInstream.QueryInterface(Components.interfaces.nsIFileInputStream);
      fileInstream.init(fl, 0x01, 0644, 0);
      fileInstream.QueryInterface(Components.interfaces.nsISeekableStream);
      fileInstream.seek(0, remoteSize);                                      // append or not to append

      dataInstream = Components.classes["@mozilla.org/binaryinputstream;1"].createInstance(Components.interfaces.nsIBinaryInputStream);
      dataInstream.setInputStream(fileInstream);
    } catch (ex) {
      this._log(DEBUG, ex);

      this._log(ERROR, gStrbundle.getFormattedString("failedUpload", [localpath]));

      try {
        dataInstream.close();
      } catch (ex) { }

      try {
        fileInstream.close();
      } catch (ex) { }

      callback(new paramikojs.ssh_exception.IOError("Couldn't open local file while uploading."));
      return;
    }

    var self = this;
    var open_callback = function(fr) {
      if (!fr || fr instanceof paramikojs.ssh_exception.IOError || fr instanceof paramikojs.ssh_exception.SFTPError) {
        try {
          dataInstream.close();
        } catch (ex) { }
        callback(fr);
        return;
      }

      //fr.set_pipelined(true); todo fixme
      fr.seek(remoteSize);

      self.put_loop(dataInstream, fr, callback, progress_callback);
    };

    this.open(remotepath, (remoteSize ? 'a' : 'w') + 'b', null, open_callback, remoteSize);
  },

  put_loop : function(dataInstream, fr, callback, progress_callback) {
    try {
      var data = dataInstream.readBytes(dataInstream.available() < 32768 ? dataInstream.available() : 32768);
      if (!data.length) {
        var close_callback = function() {
          try {
            dataInstream.close();
          } catch (ex) { }
          callback(true);
        };
        fr.close(close_callback);
        return;
      }

      var self = this;
      var write_callback = function() {
        progress_callback(data.length);
        self.put_loop(dataInstream, fr, callback, progress_callback);
      };
      fr.write(data, write_callback);
    } catch (ex) {
      callback(new paramikojs.ssh_exception.IOError("Error reading file while uploading."));
    }
  },

  /*
    Copy a remote file (C{remotepath}) from the SFTP server to the local
    host as C{localpath}.  Any exception raised by operations will be
    passed through.  This method is primarily provided as a convenience.

    @param remotepath: the remote file to copy
    @type remotepath: str
    @param localpath: the destination path on the local host
    @type localpath: str
    @param callback: optional callback function that accepts the bytes
        transferred so far and the total bytes to be transferred
        (since 1.7.4)
    @type callback: function(int, int)

    @since: 1.4
  */
  get : function(remotepath, localpath, localSize, callback, progress_callback) {
    var fl;
    var fileOutstream;
    var binaryOutstream;

    try {
      fl = localFile.init(localpath);
      localSize = localSize == -1 ? 0 : localSize;
      fileOutstream = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance(Components.interfaces.nsIFileOutputStream);

      if (localSize) {
        fileOutstream.init(fl, 0x04 | 0x10, 0644, 0);
      } else {
        fileOutstream.init(fl, 0x04 | 0x08 | 0x20, 0644, 0);
      }

      binaryOutstream = Components.classes["@mozilla.org/binaryoutputstream;1"].createInstance(Components.interfaces.nsIBinaryOutputStream);
      binaryOutstream.setOutputStream(fileOutstream);
    } catch (ex) {
      this._log(DEBUG, ex);

      this._log(ERROR, gStrbundle.getFormattedString("failedSave", [remotepath]));

      try {
        binaryOutstream.close();
      } catch (ex) { }

      try {
        fileOutstream.close();
      } catch (ex) { }

      callback(new paramikojs.ssh_exception.IOError("Couldn't open local file while downloading."));
      return;
    }

    var self = this;
    var open_callback = function(fr) {
      if (!fr || fr instanceof paramikojs.ssh_exception.IOError || fr instanceof paramikojs.ssh_exception.SFTPError) {
        try {
          binaryOutstream.close();
        } catch (ex) { }
        callback(fr);
        return;
      }

      var prefetch_callback = function() {
        self.get_loop(binaryOutstream, fr, callback, progress_callback);
      };

      fr.seek(localSize);
      fr.prefetch(prefetch_callback);
    };

    this.open(remotepath, 'rb', null, open_callback);
  },

  get_loop : function(binaryOutstream, fr, callback, progress_callback) {
    var self = this;
    var read_callback = function(data, eof) {
      try {
        if (!data.length) {
          fr.close(false);
          try {
            binaryOutstream.close();
          } catch (ex) { }
          callback(true);
          return;
        }
        progress_callback(data.length);
        binaryOutstream.writeBytes(data, data.length);
        self.get_loop(binaryOutstream, fr, callback, progress_callback);
      } catch (ex) {
        callback(new paramikojs.ssh_exception.IOError("Error writing file while downloading."));
      }
    };
    fr.read(32768, read_callback);
  },


  //  internals...


  _request : function(t, callback) {
    var self = this;
    var request_callback = function(num) {
      self._read_response(num, callback);
    };

    var arg = [];
    for (var x = 2; x < arguments.length; ++x) {
      arg.push(arguments[x]);
    }

    this._async_request(null, t, request_callback, arg);
  },

  _async_request : function(fileobj, t, request_callback, arg, msg, num) {
    // this method may be called from other threads (prefetch)
    num = num || this.request_number;
    if (!msg) {
      msg = new paramikojs.Message();
      msg.add_int(this.request_number);
      for (var x = 0; x < arg.length; ++x) {
        var item = arg[x];
        if (typeof item == "number") {
          msg.add_int(item);
        } else if (item instanceof BigInteger) {
          msg.add_int64(item);
        } else if (typeof item == "string") {
          msg.add_string(item);
        } else if (item instanceof paramikojs.SFTPAttributes) {
          item._pack(msg);
        } else {
          throw new paramikojs.ssh_exception.SFTPError('unknown type for ' + item + ' type ' + typeof item);
        }
      }

      this._expecting[num] = fileobj;
      this.request_number += 1;
    }

    var send_packet_callback = function() {
      if (request_callback) {
        request_callback(num);
      }
    };
    this._send_packet(t, msg.toString(), send_packet_callback);

    return num;
  },

  _read_response : function(waitfor, callback) {
    var self = this;
    var wait_callback = function() { self._read_response(waitfor, callback) };

    var result;
    if (this._deferred_packet) {  // due to setTimeout, we can get things out of order :-/
      var deferred_msg = new paramikojs.Message(this._deferred_packet[1]);
      var deferred_num = deferred_msg.get_int();
      if (deferred_num == waitfor) {
        result = this._deferred_packet;
        this._deferred_packet = null;
      } else {
        // wait for the proper packet to arrive
        setTimeout(wait_callback, 10);
        return;
      }
    }

    if (!result) {
      try {
        result = this._read_packet();
      } catch(ex) {
        if (ex instanceof paramikojs.ssh_exception.WaitException) {
          // waiting on socket
          setTimeout(wait_callback, 10);
          return;
        } else {
          throw ex;
        }
      }
    }

    var msg = new paramikojs.Message(result[1]);
    var num = msg.get_int();

    if (waitfor != null && waitfor != num) {  // due to setTimeout, we can get things out of order :-/
      this._deferred_packet = result;
      // wait for the proper packet to arrive
      setTimeout(wait_callback, 10);
      return;
    }

    if (!(num in this._expecting)) {
      // might be response for a file that was closed before responses came back
      this._log(DEBUG, 'Unexpected response #' + num);
      if (!waitfor) {
        // just doing a single check
        if (callback) {
          callback([null, null]);
        }
        return;
      }
      setTimeout(wait_callback, 10);
      return;
    }
    var fileobj = this._expecting[num];
    delete this._expecting[num];
    if (num == waitfor) {
      // synchronous
      if (result[0] == this.CMD_STATUS) {
        try {
          this._convert_status(msg);
        } catch(ex) {
          if (ex instanceof paramikojs.ssh_exception.EOFError) {
            if (callback) {
              callback(null, true);
            }
            return;
          } else if (ex instanceof paramikojs.ssh_exception.IOError) {
            if (callback) {
              callback(null, false, ex);
            }
            return;
          } else {
            throw ex;
          }
        }
      }
      if (callback) {
        callback([result[0], msg]);
      }
      return;
    }
    if (fileobj) {
      fileobj._async_response(result[0], msg);
    }
    if (!waitfor) {
      // just doing a single check
      if (callback) {
        callback([null, null]);
      }
      return;
    }

    setTimeout(wait_callback, 10);
  },

  _finish_responses : function(fileobj) {
    var x;
    while (x in this._expecting) {
      if (this._expecting[x] == fileobj) {
        this._read_response();
        fileobj._check_exception();
      }
    }
  },

  /*
    Raises EOFError or IOError on error status; otherwise does nothing.
  */
  _convert_status : function(msg) {
    var code = msg.get_int();
    var text = msg.get_string();
    if (code == this.SFTP_OK) {
      return;
    } else if (code == this.SFTP_EOF) {
      throw new paramikojs.ssh_exception.EOFError(text);
    } else if (code == this.SFTP_NO_SUCH_FILE) {
      throw new paramikojs.ssh_exception.IOError(text);
    } else if (code == this.SFTP_PERMISSION_DENIED) {
      throw new paramikojs.ssh_exception.IOError(text);
    } else {
      throw new paramikojs.ssh_exception.IOError(text);
    }
  },

  /*
    Return an adjusted path if we're emulating a "current working
    directory" for the server.
  */
  _adjust_cwd : function(path) {
    path = this.transport.fromUTF8.ConvertFromUnicode(path) + this.transport.fromUTF8.Finish();
    if (!this._cwd) {
      return path;
    }
    if (path.length > 0 && path[0] == '/') {
      // absolute path
      return path;
    }
    if (this._cwd == '/') {
      return this._cwd + path;
    }

    var cwd = this.transport.fromUTF8.ConvertFromUnicode(this._cwd) + this.transport.fromUTF8.Finish();
    return cwd + '/' + path;
  }
};
