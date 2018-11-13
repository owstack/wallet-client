'use strict';

var owsCommon = require('@owstack/ows-common');
var keyLib = require('@owstack/key-lib');
var Common = require('./common');
var Credentials = require('@owstack/credentials-lib');
var log = require('./log');
var PrivateKey = keyLib.PrivateKey;
var Utils = Common.Utils;
var lodash = owsCommon.deps.lodash;
var $ = require('preconditions').singleton();

/**
 * @desc Verifier constructor. Checks data given by the server
 *
 * @constructor
 */
function Verifier(context) {
  this.ctx = context;
};

/**
 * Check address
 *
 * @param {Function} credentials
 * @param {String} address
 * @returns {Boolean} true or false
 */
Verifier.checkAddress = function(credentials, address) {
  $.checkState(credentials.isComplete());

  var local = this.ctx.client.deriveAddress(address.type || credentials.addressType, credentials.publicKeyRing, address.path, credentials.m, credentials.network);
  return (local.address == address.address &&
    lodash.difference(local.publicKeys, address.publicKeys).length === 0);
};

/**
 * Check copayers
 *
 * @param {Function} credentials
 * @param {Array} copayers
 * @returns {Boolean} true or false
 */
Verifier.checkCopayers = function(credentials, copayers) {
  $.checkState(credentials.walletPrivKey);
  var walletPubKey = PrivateKey.fromString(credentials.walletPrivKey).toPublicKey().toString();

  if (copayers.length != credentials.n) {
    log.error('Missing public keys in server response');
    return false;
  }

  // Repeated xpub kes?
  var uniq = [];
  var error;
  lodash.each(copayers, function(copayer) {
    if (error) {
console.log('1');
      return;
    }

    if (uniq[copayers.xPubKey]++) {
      log.error('Repeated public keys in server response');
console.log('Repeated public keys in server response');
      error = true;
    }

    // Not signed pub keys
    if (!(copayer.encryptedName || copayer.name) || !copayer.xPubKey || !copayer.requestPubKey || !copayer.signature) {
      log.error('Missing copayer fields in server response');
console.log('Missing copayer fields in server response');
      error = true;
    } else {
      var hash = Utils.getCopayerHash(copayer.encryptedName || copayer.name, copayer.xPubKey, copayer.requestPubKey);
console.log(hash);
console.log(copayer.signature);
console.log(walletPubKey);

      if (!Utils.verifyMessage(hash, copayer.signature, walletPubKey)) {
        log.error('Invalid signatures in server response');
console.log('Invalid signatures in server response');
        error = true;
      }
    }
  });

  if (error) {
console.log('2');
    return false;
  }

  if (!lodash.includes(lodash.map(copayers, 'xPubKey'), credentials.xPubKey)) {
    log.error('Server response does not contains our public keys')
    return false;
  }
  return true;
};

Verifier.checkProposalCreation = function(args, txp, encryptingKey) {
  function strEqual(str1, str2) {
    return ((!str1 && !str2) || (str1 === str2));
  }

  if (txp.outputs.length != args.outputs.length) return false;

  for (var i = 0; i < txp.outputs.length; i++) {
    var o1 = txp.outputs[i];
    var o2 = args.outputs[i];
    if (!strEqual(o1.toAddress, o2.toAddress)) return false;
    if (!strEqual(o1.script, o2.script)) return false;
    if (o1.amount != o2.amount) return false;
    var decryptedMessage = null;
    try {
      decryptedMessage = Utils.decryptMessage(o2.message, encryptingKey);
    } catch (e) {
      return false;
    }
    if (!strEqual(o1.message, decryptedMessage)) return false;
  }

  var changeAddress;
  if (txp.changeAddress) {
    changeAddress = txp.changeAddress.address;
  }

  if (args.changeAddress && !strEqual(changeAddress, args.changeAddress)) return false;
  if (lodash.isNumber(args.feePerKb) && (txp.feePerKb != args.feePerKb)) return false;
  if (!strEqual(txp.payProUrl, args.payProUrl)) return false;

  var decryptedMessage = null;
  try {
    decryptedMessage = Utils.decryptMessage(args.message, encryptingKey);
  } catch (e) {
    return false;
  }
  if (!strEqual(txp.message, decryptedMessage)) return false;
  if (args.customData && !lodash.isEqual(txp.customData, args.customData)) return false;

  return true;
};

Verifier.checkTxProposalSignature = function(credentials, txp) {
  $.checkArgument(txp.creatorId);
  $.checkState(credentials.isComplete());

  var creatorKeys = lodash.find(credentials.publicKeyRing, function(item) {
    if (Credentials.xPubToCopayerId(item.xPubKey) === txp.creatorId) return true;
  });

  if (!creatorKeys) return false;
  var creatorSigningPubKey;

  // If the txp using a selfsigned pub key?
  if (txp.proposalSignaturePubKey) {

    // Verify it...
    if (!Utils.verifyRequestPubKey(txp.proposalSignaturePubKey, txp.proposalSignaturePubKeySig, creatorKeys.xPubKey))
      return false;

    creatorSigningPubKey = txp.proposalSignaturePubKey;
  } else {
    creatorSigningPubKey = creatorKeys.requestPubKey;
  }
  if (!creatorSigningPubKey) return false;


  var hash;
  if (parseInt(txp.version) >= 3) {
    var t = this.ctx.client.buildTx(txp);
    hash = t.uncheckedSerialize();
  } else {
    throw new Error('Transaction proposal not supported');
  }

  log.debug('Regenerating & verifying tx proposal hash -> Hash: ', hash, ' Signature: ', txp.proposalSignature);
  if (!Utils.verifyMessage(hash, txp.proposalSignature, creatorSigningPubKey))
    return false;

  if (!Verifier.checkAddress(credentials, txp.changeAddress))
    return false;

  return true;
};

Verifier.checkPaypro = function(txp, payproOpts) {
  var toAddress, amount;

  if (parseInt(txp.version) >= 3) {
    toAddress = txp.outputs[0].toAddress;
    amount = txp.amount;
  } else {
    toAddress = txp.toAddress;
    amount = txp.amount;
  }

  return (toAddress == payproOpts.toAddress && amount == payproOpts.amount);
};

/**
 * Check transaction proposal
 *
 * @param {Function} credentials
 * @param {Object} txp
 * @param {Object} Optional: paypro
 * @param {Boolean} isLegit
 */
Verifier.checkTxProposal = function(credentials, txp, opts) {
  opts = opts || {};

  if (!this.checkTxProposalSignature(credentials, txp))
    return false;

  if (opts.paypro && !this.checkPaypro(txp, opts.paypro))
    return false;

  return true;
};

module.exports = Verifier;
