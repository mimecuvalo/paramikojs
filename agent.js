/*
  Client interface for using private keys from an SSH agent running on the
  local machine.  If an SSH agent is running, this class can be used to
  connect to it and retreive L{PKey} objects which can be used when
  attempting to authenticate to remote SSH servers.
  
  Because the SSH agent protocol uses environment variables and unix-domain
  sockets, this probably doesn't work on Windows.  It does work on most
  posix platforms though (Linux and MacOS X, for example).
*/
paramikojs.Agent = function () {
  /*
    Open a session with the local machine's SSH agent, if one is running.
    If no agent is running, initialization will succeed, but L{get_keys}
    will return an empty tuple.
    
    @raise SSHException: if an SSH agent is found, but speaks an
        incompatible protocol
  */

  this.conn = null;
  this.keys = [];

  if(!(Components && Components.classes)) {
    throw new Error("Unable to use OS environment without Mozilla's Components.classes"); //FIXME
  }
  var userEnvironment = Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment);
  if (userEnvironment.exists('SSH_AUTH_SOCK') && sys.platform != 'win32') {
    var conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); // todo, fixme, doesn't work right now :-/
    var auth_sock = userEnvironment.get('SSH_AUTH_SOCK');
    try {
      conn.connect(auth_sock);
    } catch(ex) {
      // probably a dangling env var: the ssh agent is gone
      return;
    }
    this.conn = conn;
  } else if (sys.platform == 'win32') {
    var win_pageant = new paramikojs.win_pageant();
    if (win_pageant.can_talk_to_agent()) {
      this.conn = win_pageant.PageantConnection();
    } else {
      return;
    }
  } else {
    // no agent support
    return;
  }
      
  var msg = this._send_message(String.fromCharCode(paramikojs.Agent.SSH2_AGENTC_REQUEST_IDENTITIES));
  if (msg.ptype != paramikojs.Agent.SSH2_AGENT_IDENTITIES_ANSWER) {
    throw new paramikojs.ssh_exception.SSHException('could not get keys from ssh-agent');
  }

  var max = msg.result.get_int();
  for (var x = 0; x < max; ++x) {
    this.keys.push(new paramikojs.AgentKey(this, msg.result.get_string()));
    msg.result.get_string();
  }
}

paramikojs.Agent.SSH2_AGENTC_REQUEST_IDENTITIES = 11;
paramikojs.Agent.SSH2_AGENT_IDENTITIES_ANSWER = 12;
paramikojs.Agent.SSH2_AGENTC_SIGN_REQUEST = 13;
paramikojs.Agent.SSH2_AGENT_SIGN_RESPONSE = 14;

paramikojs.Agent.prototype = {

  /*
    Close the SSH agent connection.
  */
  close : function() {
    if (this.conn) {
      this.conn.close();
    }
    this.conn = null;
    this.keys = [];
  },

  /*
    Return the list of keys available through the SSH agent, if any.  If
    no SSH agent was running (or it couldn't be contacted), an empty list
    will be returned.
    
    @return: a list of keys available on the SSH agent
    @rtype: tuple of L{AgentKey}
  */
  get_keys : function() {
    return this.keys;
  },

  _send_message : function(msg) {
    var msg = msg.toString();
    this.conn.send(struct.pack('>I', msg.length) + msg);  // TODO, fixme
    var l = this._read_all(4);
    msg = new paramikojs.Message(this._read_all(struct.unpack('>I', l)[0]));
    return { 'ptype': msg.get_byte().charCodeAt(0), 'result': msg };
  },

  _read_all : function(wanted) {
    var result = this.conn.recv(wanted);  // TODO, fixme
    while (result.length < wanted) {
      if (result.length == 0) {
        throw new paramikojs.ssh_exception.SSHException('lost ssh-agent');
      }
      var extra = this.conn.recv(wanted - result.length);
      if (extra.length == 0) {
        throw new paramikojs.ssh_exception.SSHException('lost ssh-agent');
      }
      result += extra;
    }
    return result;
  }
};



/*
  Private key held in a local SSH agent.  This type of key can be used for
  authenticating to a remote server (signing).  Most other key operations
  work as expected.
 */
paramikojs.AgentKey = function(agent, blob) {
	inherit(this, new paramikojs.PKey());

  this.agent = agent;
  this.blob = blob;
  this.name = new paramikojs.Message(blob).get_string();
}

paramikojs.AgentKey.prototype = {
	toString : function() {
    return this.blob;
  },

	get_name : function() {
    return this.name;
  },

	sign_ssh_data : function(rng, data, callback) {
    var msg = new paramikojs.Message();
    msg.add_byte(String.fromCharCode(paramikojs.Agent.SSH2_AGENTC_SIGN_REQUEST));
    msg.add_string(this.blob);
    msg.add_string(data);
    msg.add_int(0);
    var msg = this.agent._send_message(msg);
    if (msg.ptype != paramikojs.Agent.SSH2_AGENT_SIGN_RESPONSE) {
      throw new paramikojs.ssh_exception.SSHException('key cannot be used for signing');
    }
    callback(msg.result.get_string());
  }
};
