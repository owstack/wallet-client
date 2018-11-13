'use strict';

var owsCommon = require('@owstack/ows-common');
var keyLib = require('@owstack/key-lib');
var Buffer = owsCommon.deps.Buffer;
var BufferReader = owsCommon.encoding.BufferReader;
var Constants = owsCommon.Constants;
var ECDSA = keyLib.crypto.ECDSA;
var Hash = owsCommon.Hash;
var HDPrivateKey = keyLib.HDPrivateKey;
var HDPublicKey = keyLib.HDPublicKey;
var PrivateKey = keyLib.PrivateKey;
var PublicKey = keyLib.PublicKey;
var Signature = keyLib.crypto.Signature;
var sjcl = require('sjcl');
var Stringify = require('json-stable-stringify');
var lodash = owsCommon.deps.lodash;
var $ = require('preconditions').singleton();

function Utils() {};

Utils.SJCL = {};

Utils.encryptMessage = function(message, encryptingKey) {
  var key = sjcl.codec.base64.toBits(encryptingKey);
  return sjcl.encrypt(key, message, lodash.defaults({
    ks: 128,
    iter: 1,
  }, Utils.SJCL));
};

Utils.decryptMessage = function(cyphertextJson, encryptingKey) {
  try {
    var key = sjcl.codec.base64.toBits(encryptingKey);
    return sjcl.decrypt(key, cyphertextJson);
  } catch (ex) {
    return cyphertextJson;
  }
};

/* TODO: It would be nice to be compatible with bitcoind signmessage. How
 * the hash is calculated there? */
Utils.hashMessage = function(text) {
  $.checkArgument(text);
  var buf = new Buffer(text);
  var ret = Hash.sha256sha256(buf);
  ret = new BufferReader(ret).readReverse();
  return ret;
};


Utils.signMessage = function(text, privKey) {
  $.checkArgument(text);
  var priv = new PrivateKey(privKey);
  var hash = Utils.hashMessage(text);
  return ECDSA.sign(hash, priv, 'little').toString();
};


Utils.verifyMessage = function(text, signature, pubKey) {
  $.checkArgument(text);
  $.checkArgument(pubKey);

  if (!signature) {
    return false;
  }

  var pub = new PublicKey(pubKey);
  var hash = Utils.hashMessage(text);

  try {
    var sig = new Signature.fromString(signature);
    return ECDSA.verify(hash, sig, pub, 'little');
  } catch (e) {
    return false;
  }
};

Utils.privateKeyToAESKey = function(privKey) {
  $.checkArgument(privKey && lodash.isString(privKey));
  $.checkArgument(PrivateKey.isValid(privKey), 'The private key received is invalid');
  var pk = PrivateKey.fromString(privKey);
  return Hash.sha256(pk.toBuffer()).slice(0, 16).toString('base64');
};

Utils.getCopayerHash = function(name, xPubKey, requestPubKey) {
  return [name, xPubKey, requestPubKey].join('|');
};

Utils.getProposalHash = function(proposalHeader) {
  function getOldHash(toAddress, amount, message, payProUrl) {
    return [toAddress, amount, (message || ''), (payProUrl || '')].join('|');
  };

  // For backwards compatibility
  if (arguments.length > 1) {
    return getOldHash.apply(this, arguments);
  }

  return Stringify(proposalHeader);
};

Utils.signRequestPubKey = function(requestPubKey, xPrivKey) {
  var priv = new HDPrivateKey(xPrivKey).deriveChild(Constants.PATHS.REQUEST_KEY_AUTH).privateKey;
  return Utils.signMessage(requestPubKey, priv);
};

Utils.verifyRequestPubKey = function(requestPubKey, signature, xPubKey) {
  var pub = (new HDPublicKey(xPubKey)).deriveChild(Constants.PATHS.REQUEST_KEY_AUTH).publicKey;
  return Utils.verifyMessage(requestPubKey, signature, pub.toString());
};

module.exports = Utils;
