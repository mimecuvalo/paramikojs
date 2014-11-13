/*
  Representation of a key that we don't know about.
*/
paramikojs.UnknownKey = function(keytype, key) {
  inherit(this, new paramikojs.PKey());

  this.keytype = keytype;
  this.key = key;
}

paramikojs.UnknownKey.prototype = {
  toString : function() {
    return this.key;
  },

  compare : function(other) {
    if (this.get_name() != other.get_name()) {
      return false;
    }
    if (this.key != other.key) {
      return false;
    }
    return true;
  },

  get_name : function() {
    return this.keytype;
  }
};

