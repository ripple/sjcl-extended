'use strict';
var sjcl = require('sjcl');
/* eslint-disable new-cap */

sjcl.ecc.ecdsa.secretKey.prototype.generateK =
function(hash, hashObject) {

  var curve = this._curve
  var qlen = this._curveBitLength;

  /* Utility functions */
  /* used to generate k and v */
  function repeat(str, times) {
    return (new Array(times + 1)).join(str);
  }
  function bits2int(bits) {

    var blen = sjcl.bitArray.bitLength(bits);

    if (blen > qlen) {
      return sjcl.bn.fromBits(sjcl.bitArray.clamp(bits, qlen));
    }
    return sjcl.bn.fromBits(bits);
  }
  function int2octets(integer) {
    var iModQ = integer.mulmod(new sjcl.bn(1), curve.r);

    var rlen = 8 * Math.ceil(qlen / 8);
    var ilen = iModQ.bitLength();

    return sjcl.bitArray.concat(
      sjcl.codec.hex.toBits(repeat('0', Math.ceil((rlen - ilen) / 4))),
      iModQ.toBits()
    );
  }
  function bits2octets(bits) {
    return int2octets(bits2int(bits).mulmod(new sjcl.bn(1), curve.r));
  }

  function hmac() {
    var params = Array.prototype.slice.call(arguments);    

    var key = params.shift();
    var hmacK = new sjcl.misc.hmac(key, hashObject);

    var bits = params[0];
    for (var i = 1; i < params.length; i++) {
      bits = sjcl.bitArray.concat(bits, params[i]); 
    }

    return hmacK.encrypt(bits);
  }

  var hlen = sjcl.bitArray.bitLength(hash);
  var x = sjcl.bn.fromBits(this.get());

  var k = sjcl.codec.hex.toBits(repeat('00', Math.ceil(hlen / 8)));
  var v = sjcl.codec.hex.toBits(repeat('01', Math.ceil(hlen / 8)));

  k = hmac(
    k,
    v, sjcl.codec.hex.toBits('00'), int2octets(x), bits2octets(hash)
  );

  v = hmac(k, v);

  k = hmac(
    k,
    v, sjcl.codec.hex.toBits('01'), int2octets(x), bits2octets(hash)
  );

  v = hmac(k, v);
  v = hmac(k, v);

  var T = sjcl.bn.fromBits(v); while (
    T.bitLength() < qlen
  ) {
    v = hmac(k, v);
    T = sjcl.bn.fromBits(sjcl.bitArray.concat(T.toBits(), v));
  }
  T = bits2int(T.toBits());

  while (!(T.greaterEquals(1)) || (T.greaterEquals(curve.r))) {
    k = hmac(
      k,
      v, sjcl.codec.hex.toBits('00')
    );

    v = hmac(k, v);
    T = sjcl.bn.fromBits(v);
    while (
      T.bitLength() < qlen
    ) {
      v = hmac(k, v);
      T = sjcl.bn.fromBits(sjcl.bitArray.concat(T.toBits(), v));
    }
    T = bits2int(T.toBits());
  }

  return T;
};

/**
* @param {bitArray} hash hash to sign.
* @param {Object} hashObject type of hash used for hmac
*   (default sjcl.hash.sha256)
* @return {bitArray} signature
*/
sjcl.ecc.ecdsa.secretKey.prototype.signDeterministic =
function(hash, hashObject) {
  hashObject = hashObject || sjcl.hash.sha256;
  var k = this.generateK(hash, hashObject);
  return this.sign(hash, undefined, undefined, k);
};
