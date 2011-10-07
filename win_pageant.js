paramikojs.win_pageant = function() {
  
}

paramikojs.win_pageant.prototype = {
  _AGENT_COPYDATA_ID : 0x804e50ba,
  _AGENT_MAX_MSGLEN : 8192,
  // Note: The WM_COPYDATA value is pulled from win32con, as a workaround
  // so we do not have to import this huge library just for this one variable.
  win32con_WM_COPYDATA : 74,

  _get_pageant_window_object : function() {
    return ctypes.windll.user32.FindWindowA('Pageant', 'Pageant'); // todo fixme
  },

  /*
    Check to see if there is a "Pageant" agent we can talk to.

    This checks both if we have the required libraries (win32all or ctypes)
    and if there is a Pageant currently running.
  */
  can_talk_to_agent : function() {
    if (this._get_pageant_window_object()) {
      return true;
    }
    return false;
  },

  _query_pageant : function(msg) {
    var hwnd = _get_pageant_window_object();  // todo fixme this whole thing!
    if (!hwnd) {
      // Raise a failure to connect exception, pageant isn't running anymore!
      return null;
    }

    // Write our pageant request string into the file (pageant will read this to determine what to do)
    var filename = tempfile.mktemp('.pag');   // todo fixme
    var map_filename = os.path.basename(filename); // todo fixme

    var f = open(filename, 'w+b');  // todo fixme
    f.write(msg);
    // Ensure the rest of the file is empty, otherwise pageant will read this
    f.write('\0' * (this._AGENT_MAX_MSGLEN - msg.length));
    // Create the shared file map that pageant will use to read from
    var pymap = mmap.mmap(f.fileno(), this._AGENT_MAX_MSGLEN, tagname=map_filename, access=mmap.ACCESS_WRITE);
    try {
      // Create an array buffer containing the mapped filename
      var char_buffer = array.array("c", map_filename + '\0');
      char_buffer_address, char_buffer_size = char_buffer.buffer_info();
      // Create a string to use for the SendMessage function call
      cds = struct.pack("LLP", this._AGENT_COPYDATA_ID, char_buffer_size, char_buffer_address);

      _buf = array.array('B', cds);
      _addr, _size = _buf.buffer_info();
      response = ctypes.windll.user32.SendMessageA(hwnd, win32con_WM_COPYDATA, _size, _addr);

      if (response > 0) {
        datalen = pymap.read(4);
        retlen = struct.unpack('>I', datalen)[0];
        return datalen + pymap.read(retlen);
      }
      return null;
    } catch(ex) {
    } finally {
      pymap.close();
      f.close();
      // Remove the file, it was temporary only
      os.unlink(filename);
    }
  },

  /*
    Mock "connection" to an agent which roughly approximates the behavior of
    a unix local-domain socket (as used by Agent).  Requests are sent to the
    pageant daemon via special Windows magick, and responses are buffered back
    for subsequent reads.
  */
  PageantConnection : {
    response : null,

    send : function(data) {
      this._response = paramikojs.win_pageant._query_pageant(data);
    },
    
    recv : function(n) {
      if (!this._response) {
        return '';
      }
      ret = this._response.substring(0, n);
      this._response = this._response.substring(n);
      if (this._response == '') {
        this._response = null;
      }
      return ret;
    },

    close : function() {}
  }
};


