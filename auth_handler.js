/*
  Internal class to handle the mechanics of authentication.
*/
paramikojs.AuthHandler = function(transport) {
  this.transport = transport;
  this.username = null;
  this.authenticated = false;
  this.auth_method = '';
  this.password = null;
  this.private_key = null;
  this.interactive_handler = null;
  this.submethods = null;
  // for server mode:
  this.auth_username = null;
  this.auth_fail_count = 0;
  this.callback = null;

  this.triedKeyboard = false;
  this.triedPublicKey = false;
}

paramikojs.AuthHandler.prototype = {
  is_authenticated : function() {
    return this.authenticated;
  },

  get_username : function() {
    if (this.transport.server_mode) {
      return this.auth_username;
    } else {
      return this.username;
    }
  },

  auth_none : function(username) {
    this.auth_method = 'none';
    this.username = username;
    this._request_auth();
  },

  auth_publickey : function(username, key) {
    this.auth_method = 'publickey';
    this.username = username;
    this.private_key = key;
    this.triedPublicKey = true;
    this._request_auth();
  },

  auth_password : function(username, password) {
    this.auth_method = 'password';
    this.username = username;
    this.password = password;
    this._request_auth();
  },

  /*
    response_list = handler(title, instructions, prompt_list)
  */
  auth_interactive : function(username, handler, submethods) {
    this.auth_method = 'keyboard-interactive';
    this.username = username;
    this.interactive_handler = handler;
    this.submethods = submethods || '';
    this.triedKeyboard = true;
    this._request_auth();
  },

  abort : function() {
    
  },


  // internals...


  _request_auth : function(self) {
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_SERVICE_REQUEST));
    m.add_string('ssh-userauth');
    this.transport._send_message(m);
  },

  _disconnect_service_not_available : function() {
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_DISCONNECT));
    m.add_int(paramikojs.DISCONNECT_SERVICE_NOT_AVAILABLE);
    m.add_string('Service not available');
    m.add_string('en');
    this.transport._send_message(m);
    this.transport.close();
  },

  _disconnect_no_more_auth : function() {
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_DISCONNECT));
    m.add_int(paramikojs.DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
    m.add_string('No more auth methods available');
    m.add_string('en');
    this.transport._send_message(m);
    this.transport.close();
  },

  _get_session_blob : function(key, service, username) {
    var m = new paramikojs.Message();
    m.add_string(this.transport.session_id);
    m.add_byte(String.fromCharCode(paramikojs.MSG_USERAUTH_REQUEST));
    m.add_string(username);
    m.add_string(service);
    m.add_string('publickey');
    m.add_boolean(1);
    m.add_string(key.get_name());
    m.add_string(key.toString());
    return m.toString();
  },

  wait_for_response : function() {
    return; // do nothing
  },

  _parse_service_request : function(m) {
    var service = m.get_string();
    if (this.transport.server_mode && service == 'ssh-userauth') {
        // accepted
        var m = new paramikojs.Message();
        m.add_byte(String.fromCharCode(paramikojs.MSG_SERVICE_ACCEPT));
        m.add_string(service);
        this.transport._send_message(m);
        return;
    }
    // dunno this one
    this._disconnect_service_not_available();
  },

  _parse_service_accept : function(m) {
    var service = m.get_string();
    if (service == 'ssh-userauth') {
      this.transport._log(DEBUG, 'userauth is OK');
      var m = new paramikojs.Message();
      m.add_byte(String.fromCharCode(paramikojs.MSG_USERAUTH_REQUEST));
      m.add_string(this.username);
      m.add_string('ssh-connection');
      m.add_string(this.auth_method);
      if (this.auth_method == 'password') {
        m.add_boolean(false);
        var password = this.password;
        try {
          password = this.transport.toUTF8.convertStringToUTF8(password, "UTF-8", 1);
        } catch(ex) {
          this.transport._log(DEBUG, ex);
        }
        m.add_string(password);
      } else if (this.auth_method == 'publickey') {
        m.add_boolean(true);
        m.add_string(this.private_key.get_name());
        m.add_string(this.private_key.toString());
        var blob = this._get_session_blob(this.private_key, 'ssh-connection', this.username);

        var self = this;
        var callback = function(sig) {
          m.add_string(sig.toString());
          self.transport._send_message(m);
        };
        this.private_key.sign_ssh_data(this.transport.rng, blob, callback); // mime: changed to support workers
        return;
      } else if (this.auth_method == 'keyboard-interactive') {
        m.add_string('');
        m.add_string(this.submethods);
      } else if (this.auth_method == 'none') {
        // do nothing
      } else {
        throw new paramikojs.ssh_exception.SSHException('Unknown auth method "' + this.auth_method + '"');
      }
      this.transport._send_message(m);
    } else {
      this.transport._log(DEBUG, 'Service request "' + service + '" accepted (?)');
    }
  },

  _send_auth_result : function(username, method, result) {
    // okay, send result
    var m = new paramikojs.Message();
    if (result == paramikojs.AUTH_SUCCESSFUL) {
      this.transport._log(INFO, 'Auth granted (' + method + ').');
      m.add_byte(String.fromCharCode(paramikojs.MSG_USERAUTH_SUCCESS));
      this.authenticated = true;
    } else {
      this.transport._log(INFO, 'Auth rejected (' + method + ').');
      m.add_byte(String.fromCharCode(paramikojs.MSG_USERAUTH_FAILURE));
      m.add_string(this.transport.server_object.get_allowed_auths(username));
      if (result == paramikojs.AUTH_PARTIALLY_SUCCESSFUL) {
        m.add_boolean(1);
      } else {
        m.add_boolean(0);
        this.auth_fail_count += 1;
      }
    }
    this.transport._send_message(m);
    if (this.auth_fail_count >= 10) {
      this._disconnect_no_more_auth();
    }
    if (result == paramikojs.AUTH_SUCCESSFUL) {
      this.transport._auth_trigger();
    }
  },

  _interactive_query : function(q) {
    // make interactive query instead of response
    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_USERAUTH_INFO_REQUEST));
    m.add_string(q.name);
    m.add_string(q.instructions);
    m.add_string('');
    m.add_int(q.prompts.length);
    for (var x = 0; x < q.prompts.length; ++x) {
      m.add_string(q.prompts[x][0]);
      m.add_boolean(q.prompts[x][1]);
    }
    this.transport._send_message(m);
  },

  _parse_userauth_request : function(m) {
    if (!this.transport.server_mode) {
        // er, uh... what?
        m = new paramikojs.Message();
        m.add_byte(String.fromCharCode(paramikojs.MSG_USERAUTH_FAILURE));
        m.add_string('none');
        m.add_boolean(0);
        this.transport._send_message(m);
        return;
    }
    if (this.authenticated) {
      // ignore
      return;
    }
    var username = m.get_string();
    var service = m.get_string();
    var method = m.get_string();
    this.transport._log(DEBUG, 'Auth request (type=' + method + ') service=' + service + ', username=' + username);
    if (service != 'ssh-connection') {
      this._disconnect_service_not_available();
      return;
    }
    if (this.auth_username && this.auth_username != username) {
      this.transport._log(INFO, 'Auth rejected because the client attempted to change username in mid-flight');
      this._disconnect_no_more_auth();
      return;
    }
    this.auth_username = username;

    var result;
    if (method == 'none') {
      result = this.transport.server_object.check_auth_none(username);
    } else if (method == 'password') {
      var changereq = m.get_boolean();
      var password = m.get_string();
      password = this.transport.fromUTF8.ConvertFromUnicode(password) + this.transport.fromUTF8.Finish();

      if (changereq) {
        // always treated as failure, since we don't support changing passwords, but collect
        // the list of valid auth types from the callback anyway
        this.transport._log(DEBUG, 'Auth request to change passwords (rejected)');
        var newpassword = m.get_string();
        newpassword = this.transport.fromUTF8.ConvertFromUnicode(newpassword) + this.transport.fromUTF8.Finish();
        result = paramikojs.AUTH_FAILED;
      } else {
        result = this.transport.server_object.check_auth_password(username, password);
      }
    } else if (method == 'publickey') {
      var sig_attached = m.get_boolean();
      var keytype = m.get_string();
      var keyblob = m.get_string();
      try {
        key = this.transport._key_info[keytype](new paramikojs.Message(keyblob));
      } catch(ex) {
        this.transport._log(INFO, 'Auth rejected: public key: ' + ex.toString());
        key = null;
      }
      if (!key) {
        this._disconnect_no_more_auth();
        return;
      }
      // first check if this key is okay... if not, we can skip the verify
      result = this.transport.server_object.check_auth_publickey(username, key);
      if (result != paramikojs.AUTH_FAILED) {
        // key is okay, verify it
        if (!sig_attached) {
          // client wants to know if this key is acceptable, before it
          // signs anything...  send special "ok" message
          m = new paramikojs.Message();
          m.add_byte(String.fromCharCode(paramikojs.MSG_USERAUTH_PK_OK));
          m.add_string(keytype);
          m.add_string(keyblob);
          this.transport._send_message(m);
          return;
        }
        var sig = new paramikojs.Message(m.get_string());
        var blob = this._get_session_blob(key, service, username);
        if (!key.verify_ssh_sig(blob, sig)) {
          this.transport._log(INFO, 'Auth rejected: invalid signature');
          result = paramikojs.AUTH_FAILED;
        }
      }
    } else if (method == 'keyboard-interactive') {
      var lang = m.get_string();
      var submethods = m.get_string();
      result = this.transport.server_object.check_auth_interactive(username, submethods);
      if (result instanceof paramikojs.InteractiveQuery) {
        // make interactive query instead of response
        this._interactive_query(result);
        return;
      }
    } else {
      result = this.transport.server_object.check_auth_none(username);
    }
    // okay, send result
    this._send_auth_result(username, method, result);
  },

  _parse_userauth_success : function(m) {
    this.transport._log(INFO, 'Authentication (' + this.auth_method + ') successful!');
    this.authenticated = true;
    this.transport._auth_trigger();
    this.transport.auth_callback(true);
  },

  _parse_userauth_failure : function(m) {
    var authlist = m.get_list();
    var partial = m.get_boolean();
    var nextOptions = null;
    if (partial) {
      this.transport._log(INFO, 'Authentication continues...');
      this.transport._log(DEBUG, 'Methods: ' + authlist.toString());
      //this.transport.saved_exception = new paramikojs.ssh_exception.PartialAuthentication(authlist);
      nextOptions = authlist;
    } else if (authlist.indexOf(this.auth_method) == -1) {
      this.transport._log(DEBUG, 'Authentication type (' + this.auth_method + ') not permitted.');
      this.transport._log(DEBUG, 'Allowed methods: ' + authlist.toString());
      //this.transport.saved_exception = new paramikojs.ssh_exception.BadAuthenticationType('Bad authentication type', authlist);
      nextOptions = authlist;
    } else {
      this.transport._log(INFO, 'Authentication (' + this.auth_method + ') failed.');
    }
    this.authenticated = false;
    this.username = null;
    this.transport.auth_callback(false, authlist, this.triedKeyboard, this.triedPublicKey);
  },

  _parse_userauth_banner : function(m) {
    var banner = m.get_string();
    var lang = m.get_string();
    this.transport._log(INFO, 'Auth banner: ' + banner);
    // who cares.
  },

  _parse_userauth_info_request : function(m) {
    if (this.auth_method != 'keyboard-interactive') {
      throw new paramikojs.ssh_exception.SSHException('Illegal info request from server');
    }
    var title = m.get_string();
    var instructions = m.get_string();
    m.get_string();  // lang
    var prompts = m.get_int();
    var prompt_list = [];
    for (var x = 0; x < prompts; ++x) {
      prompt_list.push([m.get_string(), m.get_boolean()]);
    }
    var response_list = this.interactive_handler(title, instructions, prompt_list);
    
    m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.MSG_USERAUTH_INFO_RESPONSE));
    m.add_int(response_list.length);
    for (var x = 0; x < response_list.length; ++x) {
      m.add_string(response_list[x]);
    }
    this.transport._send_message(m);
  },

  _parse_userauth_info_response : function(m) {
    if (!this.transport.server_mode) {
      throw new paramikojs.ssh_exception.SSHException('Illegal info response from server');
    }
    var n = m.get_int();
    var responses = [];
    for (var x = 0; x < n; ++x) {
      responses.append(m.get_string());
    }
    var result = this.transport.server_object.check_auth_interactive_response(responses);
    if (result instanceof paramikojs.InteractiveQuery) {
      // make interactive query instead of response
      this._interactive_query(result);
      return;
    }
    this._send_auth_result(this.auth_username, 'keyboard-interactive', result);
  },

  _handler_table : {
    5: function(self, m) { self._parse_service_request(m) },
    6: function(self, m) { self._parse_service_accept(m) },
    50: function(self, m) { self._parse_userauth_request(m) },
    51: function(self, m) { self._parse_userauth_failure(m) },
    52: function(self, m) { self._parse_userauth_success(m) },
    53: function(self, m) { self._parse_userauth_banner(m) },
    60: function(self, m) { self._parse_userauth_info_request(m) },
    61: function(self, m) { self._parse_userauth_info_response(m) }
  }  
};
