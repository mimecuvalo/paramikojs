kryptos.random.Fortuna.FortunaPool = function() {
  /*
    Fortuna pool type

    This object acts like a hash object, with the following differences:

        - It keeps a count (the .length attribute) of the number of bytes that
          have been added to the pool
        - It supports a .reset() method for in-place reinitialization
        - The method to add bytes to the pool is .append(), not .update().
  */
  this.reset();
}

kryptos.random.Fortuna.FortunaPool.prototype = {
  digest_size : kryptos.random.Fortuna.SHAd256.digest_size,

  append : function(data) {
    this._h.update(data);
    this.length += data.length;
  },

  digest : function() {
    return this._h.digest();
  },

  reset : function() {
    this._h = new kryptos.random.Fortuna.SHAd256();
    this.length = 0;
  }
};


kryptos.random.Fortuna.which_pools = function(r) {
  /*
    Return a list of pools indexes (in range(32)) that are to be included during reseed number r.

    According to _Practical Cryptography_, chapter 10.5.2 "Pools":

        "Pool P_i is included if 2**i is a divisor of r.  Thus P_0 is used
        every reseed, P_1 every other reseed, P_2 every fourth reseed, etc."
  */
  // This is a separate function so that it can be unit-tested.

  var retval = [];
  var mask = 0;
  for (var i = 0; i < 32; ++i) {
    // "Pool P_i is included if 2**i is a divisor of [reseed_count]"
    if ((r & mask) == 0) {
      retval.push(i);
    } else {
      break;   // optimization.  once this fails, it always fails
    }
    mask = (mask << 1) | 1;
  }
  return retval;
}


kryptos.random.Fortuna.FortunaAccumulator = function() {
  this.reseed_count = 0;
  this.generator = new kryptos.random.Fortuna.FortunaGenerator.AESGenerator();
  this.last_reseed = null;

  // Initialize 32 FortunaPool instances.
  // NB: This is _not_ equivalent to [FortunaPool()]*32, which would give
  // us 32 references to the _same_ FortunaPool instance (and cause the
  // assertion below to fail).
  this.pools = [];
  for (var i = 0; i < 32; ++i) { // 32 pools
    this.pools.push(new kryptos.random.Fortuna.FortunaPool());
  }
}

kryptos.random.Fortuna.FortunaAccumulator.prototype = {
  min_pool_size : 64,       // TODO: explain why
  reseed_interval : 0.100,  // 100 ms    TODO: explain why

  random_data : function(bytes) {
    var current_time = new Date();
    if (this.last_reseed > current_time) {
      // warnings.warn("Clock rewind detected. Resetting last_reseed.", ClockRewindWarning)
      this.last_reseed = null;
    }
    if (this.pools[0].length >= this.min_pool_size &&
        (!this.last_reseed ||
         current_time > this.last_reseed + this.reseed_interval)) {
      this._reseed(current_time);
    }
    // The following should fail if we haven't seeded the pool yet.
    return this.generator.pseudo_random_data(bytes);
  },

  _reseed : function(current_time) {
    if (!current_time) {
      current_time = new Date();
    }
    var seed = [];
    this.reseed_count += 1;
    this.last_reseed = current_time;
    var which_pools = kryptos.random.Fortuna.which_pools(this.reseed_count);
    for (var i = 0; i < which_pools.length; ++i) {
      seed.push(this.pools[i].digest());
      this.pools[i].reset();
    }

    seed = seed.join("");
    this.generator.reseed(seed);
  },

  add_random_event : function(source_number, pool_number, data) {
    this.pools[pool_number].append(String.fromCharCode(source_number));
    this.pools[pool_number].append(String.fromCharCode(data.length));
    this.pools[pool_number].append(data);
  }
};
