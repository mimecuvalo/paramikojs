paramikojs.BER = function (content) {
	this.content = content;
  this.idx = 0;
}

paramikojs.BER.prototype = {
	toString : function() {
    return this.content;
  },

  decode : function() {
    return this.decode_next();
  },
    
  decode_next : function() {
    if (this.idx >= this.content.length) {
      return null;
    }
    var ident = this.content[this.idx].charCodeAt(0);
    var t;
    this.idx += 1;
    if ((ident & 31) == 31) {
      // identifier > 30
      ident = 0;
      while (this.idx < this.content.length) {
        t = this.content[this.idx].charCodeAt(0);
        this.idx += 1;
        ident = (ident << 7) | (t & 0x7f);
        if (!(t & 0x80)) {
          break;
        }
      }
    }
    if (this.idx >= this.content.length) {
      return null;
    }
    // now fetch length
    var size = this.content[this.idx].charCodeAt(0);
    this.idx += 1;
    if (size & 0x80) {
      // more complimicated...
      // FIXME: theoretically should handle indefinite-length (0x80)
      t = size & 0x7f;
      if (this.idx + t > this.content.length) {
        return null;
      }
      size = paramikojs.util.inflate_long(this.content.substring(this.idx, this.idx + t), true).intValue();
      this.idx += t;
    }
    if (this.idx + size > this.content.length) {
      // can't fit
      return null;
    }
    var data = this.content.substring(this.idx, this.idx + size);
    this.idx += size;
    // now switch on id
    if (ident == 0x30) {
      // sequence
      return this.decode_sequence(data);
    } else if (ident == 2) {
      // int
      return paramikojs.util.inflate_long(data);
    } else {
      // 1: boolean (00 false, otherwise true)
      throw new paramikojs.ssh_exception.BERException('Unknown ber encoding type ' + ident + ' (robey is lazy)');
    }
  },

  decode_sequence : function(data) {
    var out = [];
    var b = new paramikojs.BER(data);
    while (true) {
      var x = b.decode_next();
      if (!x) {
        break;
      }
      out.push(x);
    }
    return out;
  },

  encode_tlv : function(ident, val) {
    // no need to support ident > 31 here
    this.content += String.fromCharCode(ident);
    if (val.length > 0x7f) {
      var lenstr = paramikojs.util.deflate_long(val.length);
      this.content += String.fromCharCode(0x80 + lenstr.length) + lenstr;
    } else {
      this.content += String.fromCharCode(val.length);
    }
    this.content += val;
  },

  encode : function(x) {
    if (typeof x == "boolean") {
      if (x) {
        this.encode_tlv(1, '\xff');
      } else {
        this.encode_tlv(1, '\x00');
      }
    } else if (typeof x == "number") {
      this.encode_tlv(2, paramikojs.util.deflate_long(x));
    } else if (typeof x == "string") {
      this.encode_tlv(4, x);
    } else if (x instanceof Array) {
      this.encode_tlv(0x30, this.encode_sequence(x));
    } else {
      throw new paramikojs.ssh_exception.BERException('Unknown type for encoding: ' + typeof x);
    }
  },

  encode_sequence : function(data) {
    var b = new paramikojs.BER();
    for (var x = 0; x < data.length; ++x) {
      b.encode(data[x]);
    }
    return str(b);
  }
};
