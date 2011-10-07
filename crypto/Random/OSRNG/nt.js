//Components.utils.import("resource://gre/modules/ctypes.jsm");

crypto.random.OSRNG.WindowsRNG = function() {
  this.__winrand = new crypto.random.OSRNG.winrandom();
}

crypto.random.OSRNG.WindowsRNG.prototype = {
  flush : function() {
    /*
      Work around weakness in Windows RNG.

      The CryptGenRandom mechanism in some versions of Windows allows an
      attacker to learn 128 KiB of past and future output.  As a workaround,
      this function reads 128 KiB of 'random' data from Windows and discards
      it.

      For more information about the weaknesses in CryptGenRandom, see
      _Cryptanalysis of the Random Number Generator of the Windows Operating
      System_, by Leo Dorrendorf and Zvi Gutterman and Benny Pinkas
      http://eprint.iacr.org/2007/419
    */

    // flush is called many, many times externally and slows down windows significantly
    // the double flush in the read function should suffice for security
    // if I am in error, please contact me with an explanation
    //this.__winrand.get_bytes(128*1024);
  },

  read : function(N, dontFlush) {
    // Unfortunately, research shows that CryptGenRandom doesn't provide
    // forward secrecy and fails the next-bit test unless we apply a
    // workaround, which we do here.  See http://eprint.iacr.org/2007/419
    // for information on the vulnerability.
    if (!dontFlush) {
      this.__winrand.get_bytes(128*1024);
    }

    this.__winrand.get_bytes(N);
    var str = "";   // todo fixme - use native array types, and move to chrome worker
    for (var x = 0; x < N; ++x) {
      str += String.fromCharCode(this.__winrand.buffer[this.__winrand.index - N + x]);
    }

    if (!dontFlush) {
      this.__winrand.get_bytes(128*1024);
    }

    return str;
  }
};


/*
 * Uses Windows CryptoAPI CryptGenRandom to get random bytes.
 * The "new" method returns an object, whose "get_bytes" method
 * can be called repeatedly to get random bytes, seeded by the
 * OS.  See the description in the comment at the end.
 * 
 * If you have the Intel Security Driver header files (icsp4ms.h)
 * for their hardware random number generator in the 810 and 820 chipsets,
 * then define HAVE_INTEL_RNG.
 *
 * =======================================================================
 * The contents of this file are dedicated to the public domain.  To the
 * extent that dedication to the public domain is not available, everyone
 * is granted a worldwide, perpetual, royalty-free, non-exclusive license
 * to exercise all rights associated with the contents of this file for
 * any purpose whatsoever.  No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =======================================================================
 *
 */

/* Author: Mark Moraes */


/*
  new([provider], [provtype]): Returns an object handle to Windows
  CryptoAPI that can be used to access a cryptographically strong
  pseudo-random generator that uses OS-gathered entropy.
  Provider is a string that specifies the Cryptographic Service Provider
  to use, default is the default OS CSP.
  provtype is an integer specifying the provider type to use, default
  is 1 (PROV_RSA_FULL)
*/

crypto.random.OSRNG.winrandom = function() {
  try {
    this.advapi32 = ctypes.open("advapi32.dll");
    const PROV_RSA_FULL = 1;
    const CRYPT_VERIFYCONTEXT = 0xF0000000;
    const CRYPT_SILENT = 0x40;

    var provtype = PROV_RSA_FULL;
    var hcp = ctypes.unsigned_long(0);
    var provname = null;
    var ulongPtrType = new ctypes.PointerType(ctypes.unsigned_long);

    var CryptAcquireContextW = this.advapi32.declare("CryptAcquireContextW", ctypes.winapi_abi, ctypes.bool,
            ulongPtrType, ctypes.jschar.ptr, ctypes.jschar.ptr, ctypes.uint32_t, ctypes.uint32_t);

    if (!CryptAcquireContextW(hcp.address(), null, provname, provtype, (CRYPT_VERIFYCONTEXT | CRYPT_SILENT) >>> 0)) {
      return null;
    }

    this.CryptGenRandom = this.advapi32.declare("CryptGenRandom", ctypes.winapi_abi, ctypes.bool,
              ctypes.unsigned_long, ctypes.uint32_t, ctypes.unsigned_char.ptr);
  } catch(ex) {
    throw ex;
  }

  this.hcp = hcp;
  window.addEventListener("unload", this.close.bind(this), false);
	return this;
}

/*
  get_bytes(nbytes, [userdata]]): Returns nbytes of random data
  from Windows CryptGenRandom.
  userdata is a string with any additional entropic data that the
  user wishes to provide.
*/

crypto.random.OSRNG.winrandom.prototype = {
  buffer : "",
  index : 0,

  // this function has been changed to call CryptGenRandom less - it's expensive
  // and we do a hell of a lot of flushing
  get_bytes : function(n) {
    if (n <= 0) {
      return;
    }

    if (this.index + n < this.buffer.length) {
      this.index += n;
      return;
    }

    var length = Math.max(1024 * 1024, n);    // 1MB of memory
    var arrayType = ctypes.ArrayType(ctypes.unsigned_char);
    var buf = new arrayType(length);
    var bufPtr = ctypes.cast(buf, ctypes.unsigned_char).address();

    if (!this.CryptGenRandom(this.hcp, length, bufPtr)) {
      return null;
    }

    this.buffer = buf;
    this.index = n;
  },

  close : function() {
    try {
      var CryptReleaseContext = this.advapi32.declare("CryptReleaseContext", ctypes.winapi_abi, ctypes.bool,
              ctypes.unsigned_long, ctypes.uint32_t);
      CryptReleaseContext(this.hcp, 0);
    } catch(ex) {
      throw ex;
    } finally {
      this.advapi32.close();
    }
  }
}

/*

CryptGenRandom usage is described in
http://msdn.microsoft.com/library/en-us/security/security/cryptgenrandom.asp
and many associated pages on Windows Cryptographic Service
Providers, which say:

	With Microsoft CSPs, CryptGenRandom uses the same
	random number generator used by other security
	components. This allows numerous processes to
	contribute to a system-wide seed. CryptoAPI stores
	an intermediate random seed with every user. To form
	the seed for the random number generator, a calling
	application supplies bits it might havefor instance,
	mouse or keyboard timing inputthat are then added to
	both the stored seed and various system data and
	user data such as the process ID and thread ID, the
	system clock, the system time, the system counter,
	memory status, free disk clusters, the hashed user
	environment block. This result is SHA-1 hashed, and
	the output is used to seed an RC4 stream, which is
	then used as the random stream and used to update
	the stored seed.

The only other detailed description I've found of the
sources of randomness for CryptGenRandom is this excerpt
from a posting
http://www.der-keiler.de/Newsgroups/comp.security.ssh/2002-06/0169.html

From: Jon McClelland (dowot69@hotmail.com) 
Date: 06/12/02 
... 
 
Windows, call a function such as CryptGenRandom, which has two of 
the properties of a good random number generator, unpredictability and 
even value distribution. This function, declared in Wincrypt.h, is 
available on just about every Windows platform, including Windows 95 
with Internet Explorer 3.02 or later, Windows 98, Windows Me, Windows 
CE v3, Windows NT 4, Windows 2000, and Windows XP. 
 
CryptGenRandom gets its randomness, also known as entropy, from many 
sources in Windows 2000, including the following: 
The current process ID (GetCurrentProcessID). 
The current thread ID (GetCurrentThreadID). 
The ticks since boot (GetTickCount). 
The current time (GetLocalTime). 
Various high-precision performance counters (QueryPerformanceCounter). 
A Message Digest 4 (MD4) hash of the user's environment block, which 
includes username, computer name, and search path. 
 
High-precision internal CPU counters, such as RDTSC, RDMSR, RDPMC (x86 
only-more information about these counters is at 
developer.intel.com/software/idap/resources/technical_collateral/pentiumii/RDTSCPM1.HTM 
<http://developer.intel.com>). 
 
Low-level system information, such as idle time, kernel time, 
interrupt times, commit limit, page read count, cache read count, 
nonpaged pool allocations, alignment fixup count, operating system 
lookaside information. 
 
Such information is added to a buffer, which is hashed using MD4 and 
used as the key to modify a buffer, using RC4, provided by the user. 
(Refer to the CryptGenRandom documentation in the Platform SDK for 
more information about the user-provided buffer.) Hence, if the user 
provides additional data in the buffer, this is used as an element in 
the witches brew to generate the random data. The result is a 
cryptographically random number generator. 
Also, note that if you plan to sell your software to the United States 
federal government, you'll need to use FIPS 140-1-approved algorithms. 
The default versions of CryptGenRandom in Microsoft Windows CE v3, 
Windows 95, Windows 98, Windows Me, Windows 2000, and Windows XP are 
FIPS-approved. Obviously FIPS-140 compliance is necessary but not 
sufficient to provide a properly secure source of random data. 
 
*/
/*
[Update: 2007-11-13]
CryptGenRandom does not necessarily provide forward secrecy or reverse
secrecy.  See the paper by Leo Dorrendorf and Zvi Gutterman and Benny
Pinkas, _Cryptanalysis of the Random Number Generator of the Windows
Operating System_, Cryptology ePrint Archive, Report 2007/419,
http://eprint.iacr.org/2007/419
*/
