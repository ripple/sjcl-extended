var assert = require('assert');
var sjcl   = require('../src');

describe('SJCL ECDSA Canonicalization', function() {
  var key = new sjcl.ecc.ecdsa.secretKey(sjcl.ecc.curves.k256, new sjcl.bn(1));
  
  describe('canonicalizeSignature', function() {
    it('should canonicalize non-canonical signatures', function () {
      var rs = sjcl.codec.hex.toBits("27ce1b914045ba7e8c11a2f2882cb6e07a19d4017513f12e3e363d71dc3fff0fb0a0747ecc7b4ca46e45b3b32b6b2a066aa0249c027ef11e5bce93dab756549c");
      rs = key.canonicalizeSignature(rs);
      assert.strictEqual(sjcl.codec.hex.fromBits(rs), "27ce1b914045ba7e8c11a2f2882cb6e07a19d4017513f12e3e363d71dc3fff0f4f5f8b813384b35b91ba4c4cd494d5f8500eb84aacc9af1d6403cab218dfeca5");
    });

    it('should not touch canonical signatures', function () {
      var rs = sjcl.codec.hex.toBits("5c32bc2b4d34e27af9fb66eeea0f47f6afb3d433658af0f649ebae7b872471ab7d23860688aaf9d8131f84cfffa6c56bf9c32fd8b315b2ef9d6bcb243f7a686c");
      rs = key.canonicalizeSignature(rs);
      assert.strictEqual(sjcl.codec.hex.fromBits(rs), "5c32bc2b4d34e27af9fb66eeea0f47f6afb3d433658af0f649ebae7b872471ab7d23860688aaf9d8131f84cfffa6c56bf9c32fd8b315b2ef9d6bcb243f7a686c");
    });
  });
});
