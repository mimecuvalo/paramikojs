crypto.random.OSRNG.DevURandomRNG = function() {
  var file = localFile.init("/dev/urandom");
  this.fstream = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance(Components.interfaces.nsIFileInputStream);
  this.fstream.init(file, -1, 0, 0);
  this.dataInstream = Components.classes["@mozilla.org/binaryinputstream;1"].createInstance(Components.interfaces.nsIBinaryInputStream);
  this.dataInstream.setInputStream(this.fstream);

  window.addEventListener("unload", this.close.bind(this), false);
}

crypto.random.OSRNG.DevURandomRNG.prototype = {
  flush : function() {
    // pass
  },

  read : function(N) {
    return this.dataInstream.readBytes(N);
  },

  close: function() {
    this.dataInstream.close();
  }
};
