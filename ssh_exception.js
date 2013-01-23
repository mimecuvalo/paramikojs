paramikojs.ssh_exception = {}

/*
  Exception raised by failures in SSH2 protocol negotiation or logic errors.
*/
paramikojs.ssh_exception.SSHException = function(message) {
	this.message = message;
  this.custom = true;
  this.name = "SSHException";
};

paramikojs.ssh_exception.SSHException.prototype.toString = function () {
  return this.name + ': "' + this.message + '"';
}

paramikojs.ssh_exception.WaitException = function(message) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "WaitException";
}

paramikojs.ssh_exception.CipherException = function(message) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "CipherException";
}

paramikojs.ssh_exception.EOFError = function(message) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "EOFError";
}

paramikojs.ssh_exception.IOError = function(message) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "IOError";
}

paramikojs.ssh_exception.SFTPError = function(message) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "SFTPError";
}

paramikojs.ssh_exception.UserRequestedDisconnect = function(message) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "UserRequestedDisconnect";
}

paramikojs.ssh_exception.IsPuttyKey = function(message, lines) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "IsPuttyKey";
  this.lines = lines;
}

paramikojs.ssh_exception.BERException = function(message) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "BERException";
}

paramikojs.ssh_exception.NeedRekeyException = function(message) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "NeedRekeyException";
}

/*
  Exception raised when authentication failed for some reason.  It may be
  possible to retry with different credentials.  (Other classes specify more
  specific reasons.)
  
  @since: 1.6
*/
paramikojs.ssh_exception.AuthenticationException = function(message) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "AuthenticationException";
}

/*
  Exception raised when a password is needed to unlock a private key file.
*/
paramikojs.ssh_exception.PasswordRequiredException = function(message) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "PasswordRequiredException";
}

/*
  Exception raised when an authentication type (like password) is used, but
  the server isn't allowing that type.  (It may only allow public-key, for
  example.)
  
  @ivar allowed_types: list of allowed authentication types provided by the
      server (possible values are: C{"none"}, C{"password"}, and
      C{"publickey"}).
  @type allowed_types: list
  
  @since: 1.1
*/
paramikojs.ssh_exception.BadAuthenticationType = function(message, types) {
  var baseEx = new paramikojs.ssh_exception.SSHException(message);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "BadAuthenticationType";
  this.allowed_types = types;
}

paramikojs.ssh_exception.BadAuthenticationType.prototype.toString = function () {
  return this.name + ': "' + this.message + '"' + '(allowed_types=' + JSON.stringify(this.allowed_types) + ')';
}

/*
  An internal exception thrown in the case of partial authentication.
*/
paramikojs.ssh_exception.PartialAuthentication = function(types) {
  var baseEx = new paramikojs.ssh_exception.SSHException('partial authentication');
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "PartialAuthentication";
  this.allowed_types = types;
}

/*
  Exception raised when an attempt to open a new L{Channel} fails.
  
  @ivar code: the error code returned by the server
  @type code: int
  
  @since: 1.6
*/
paramikojs.ssh_exception.ChannelException = function(code, text) {
  var baseEx = new paramikojs.ssh_exception.SSHException(text);
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "ChannelException";
  this.code = code;
}

/*
  The host key given by the SSH server did not match what we were expecting.
  
  @ivar hostname: the hostname of the SSH server
  @type hostname: str
  @ivar key: the host key presented by the server
  @type key: L{PKey}
  @ivar expected_key: the host key expected
  @type expected_key: L{PKey}
  
  @since: 1.6
*/
paramikojs.ssh_exception.BadHostKeyException = function(hostname, got_key, expected_key) {
  var baseEx = new paramikojs.ssh_exception.SSHException('Host key for server ' + hostname + ' does not match!');
  inherit(this, baseEx);
  this.toString = baseEx.toString;
  this.name = "BadHostKeyException";
  this.hostname = hostname;
  this.key = got_key;
  this.expected_key = expected_key;
}
