paramikojs.SFTPAttributes = function () {
  /*
    Create a new (empty) SFTPAttributes object.  All fields will be empty.
  */
  this._flags = 0;
  this.st_size = null;
  this.st_uid = null;
  this.st_gid = null;
  this.st_mode = null;
  this.st_atime = null;
  this.st_mtime = null;
  this.attr = {};
}

paramikojs.SFTPAttributes.prototype = {
  /*
    Representation of the attributes of a file (or proxied file) for SFTP in
    client or server mode.  It attemps to mirror the object returned by
    C{os.stat} as closely as possible, so it may have the following fields,
    with the same meanings as those returned by an C{os.stat} object:
        - st_size
        - st_uid
        - st_gid
        - st_mode
        - st_atime
        - st_mtime

    Because SFTP allows flags to have other arbitrary named attributes, these
    are stored in a dict named C{attr}.  Occasionally, the filename is also
    stored, in C{filename}.
  */

  FLAG_SIZE : 1,
  FLAG_UIDGID : 2,
  FLAG_PERMISSIONS : 4,
  FLAG_AMTIME : 8,
  FLAG_EXTENDED : 0x80000000,

  /*
    Create an SFTPAttributes object from an existing C{stat} object (an
    object returned by C{os.stat}).

    @param obj: an object returned by C{os.stat} (or equivalent).
    @type obj: object
    @param filename: the filename associated with this file.
    @type filename: str
    @return: new L{SFTPAttributes} object with the same attribute fields.
    @rtype: L{SFTPAttributes}
  */
  from_stat : function(obj, filename) {
    var attr = this;
    attr.st_size = obj.st_size;
    attr.st_uid = obj.st_uid;
    attr.st_gid = obj.st_gid;
    attr.st_mode = obj.st_mode;
    attr.st_atime = obj.st_atime;
    attr.st_mtime = obj.st_mtime;
    if (filename) {
      attr.filename = filename;
    }
    return attr;
  },


  //  internals...


  _from_msg : function(msg, filename, longname) {
    var attr = this;
    attr._unpack(msg);
    if (filename) {
      attr.filename = filename;
    }
    if (longname) {
      attr.longname = longname;
    }
    return attr;
  },

  _unpack : function(msg) {
    this._flags = msg.get_int();
    if (this._flags & this.FLAG_SIZE) {
      this.st_size = msg.get_int64();
    }
    if (this._flags & this.FLAG_UIDGID) {
      this.st_uid = msg.get_int();
      this.st_gid = msg.get_int();
    }
    if (this._flags & this.FLAG_PERMISSIONS) {
      this.st_mode = msg.get_int();
    }
    if (this._flags & this.FLAG_AMTIME) {
      this.st_atime = msg.get_int();
      this.st_mtime = msg.get_int();
    }
    if (this._flags & this.FLAG_EXTENDED) {
      var count = msg.get_int();
      for (var x = 0; x < count.length; ++x) {
        this.attr[msg.get_string()] = msg.get_string();
      }
    }
  },

  _pack : function(msg) {
    this._flags = 0;
    if (this.st_size) {
      this._flags |= this.FLAG_SIZE;
    }
    if (this.st_uid && this.st_gid) {
      this._flags |= this.FLAG_UIDGID;
    }
    if (this.st_mode) {
      this._flags |= this.FLAG_PERMISSIONS;
    }
    if (this.st_atime && this.st_mtime) {
      this._flags |= this.FLAG_AMTIME;
    }
    var i;
    for (i in this.attr) {  // lamesauce :-/
      break;
    }
    if (i) {
      this._flags |= this.FLAG_EXTENDED;
    }
    msg.add_int(this._flags);
    if (this._flags & this.FLAG_SIZE) {
      msg.add_int64(this.st_size);
    }
    if (this._flags & this.FLAG_UIDGID) {
      msg.add_int(this.st_uid);
      msg.add_int(this.st_gid);
    }
    if (this._flags & this.FLAG_PERMISSIONS) {
      msg.add_int(this.st_mode);
    }
    if (this._flags & this.FLAG_AMTIME) {
      // throw away any fractional seconds
      msg.add_int(this.st_atime);
      msg.add_int(this.st_mtime);
    }
    if (this._flags & this.FLAG_EXTENDED) {
      msg.add_int(this.attr.length);
      for (var key in this.attr) {
        msg.add_string(key);
        msg.add_string(this.attr[key]);
      }
    }
  },

  _rwx : function(n, suid, sticky) {
    if (suid) {
      suid = 2;
    }
    var out = '-r'.charCodeAt(n >> 2) + '-w'.charCodeAt((n >> 1) & 1);
    if (sticky) {
      out += '-xTt'.charCodeAt(suid + (n & 1));
    } else {
      out += '-xSs'.charCodeAt(suid + (n & 1));
    }
    return out;
  },

  toString : function() {
    // todo, implement if necessary
  }
};
