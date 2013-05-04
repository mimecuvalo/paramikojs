kryptos.random.OSRNG.BrowserRNG = function() {
  
}

kryptos.random.OSRNG.BrowserRNG.prototype = {
  flush : function() {
    // pass
  },

  read : function(N) {
    var array = new Uint8Array(N);
    crypto.getRandomValues(array);

    var str = "";   // todo fixme - use native array types, and move to chrome worker
    for (var x = 0; x < N; ++x) {
      str += String.fromCharCode(array[x]);
    }

    return str;
  },

  close: function() {
    // pass
  }
};
