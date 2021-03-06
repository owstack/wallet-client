'use strict';

var owsCommon = require('@owstack/ows-common');
var keyLib = require('@owstack/key-lib');
var Credentials = require('@owstack/credentials-lib');
var Log = require('./common/log');
var PrivateKey = keyLib.PrivateKey;
var lodash = owsCommon.deps.lodash;
var $ = require('preconditions').singleton();

/**
 * @desc Verifier constructor. Checks data given by the server.
 *
 * @constructor
 */
class Verifier {
  constructor(context, opts, walletClient) {
    this.walletClient = walletClient;

    // Context defines the coin network and is set by the implementing client in
    // order to instance this base client; e.g., btc-client.
    context.inject(this);

    opts = opts || {};
    this.log = new Log(opts.log);
  }
};

/**
 * Check address
 *
 * @param {Function} credentials
 * @param {String} address
 * @returns {Boolean} true or false
 */
Verifier.prototype.checkAddress = function(address) {
  $.checkState(this.walletClient.isComplete());

  var local = this.walletClient.deriveAddress(
    address.type || this.walletClient.credentials.addressType,
    this.walletClient.credentials.publicKeyRing, 
    address.path, 
    this.walletClient.credentials.m, 
    this.walletClient.credentials.networkName);

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
Verifier.prototype.checkCopayers = function(credentials, copayers) {
  var self = this;
  $.checkState(credentials.privKey);
  var walletPubKey = PrivateKey.fromString(credentials.privKey).toPublicKey().toString();

  if (copayers.length != credentials.n) {
    self.log.error('Missing public keys in server response');
    return false;
  }

  // Repeated xpub kes?
  var uniq = [];
  var error;
  lodash.each(copayers, function(copayer) {
    if (error) {
      return;
    }

    if (uniq[copayers.xPubKey]++) {
      self.log.error('Repeated public keys in server response');
      error = true;
    }

    // Not signed pub keys
    if (!(copayer.encryptedName || copayer.name) || !copayer.xPubKey || !copayer.requestPubKeys) {
      self.log.error('Missing copayer fields in server response');
      error = true;
    } else {
      var hash = self.ctx.Utils.getCopayerHash(copayer.encryptedName || copayer.name, copayer.xPubKey, copayer.requestPubKeys[0].key);
      if (!self.ctx.Utils.verifyMessage(hash, copayer.requestPubKeys[0].signature, walletPubKey)) {
        self.log.error('Invalid signatures in server response');
        error = true;
      }
    }
  });

  if (error) {
    return false;
  }

  if (!lodash.includes(lodash.map(copayers, 'xPubKey'), credentials.xPubKey)) {
    self.log.error('Server response does not contains our public keys')
    return false;
  }
  return true;
};

Verifier.prototype.checkProposalCreation = function(args, txp, encryptingKey) {
  var self = this;
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
      decryptedMessage = self.ctx.Utils.decryptMessage(o2.message, encryptingKey);
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
    decryptedMessage = self.ctx.Utils.decryptMessage(args.message, encryptingKey);
  } catch (e) {
    return false;
  }
  if (!strEqual(txp.message, decryptedMessage)) return false;
  if (args.customData && !lodash.isEqual(txp.customData, args.customData)) return false;

  return true;
};

Verifier.prototype.checkTxProposalSignature = function(credentials, txp) {
  var self = this;
  $.checkArgument(txp.creatorId);
  $.checkState(self.walletClient.isComplete());

  var creatorKeys = lodash.find(credentials.publicKeyRing, function(item) {
    if (Credentials.xPubToCopayerId(item.xPubKey) === txp.creatorId) {
      return true;
    }
  });
  if (!creatorKeys) {
    return false;
  }
  var creatorSigningPubKey;

  // If the txp using a selfsigned pub key?
  if (txp.proposalSignaturePubKey) {
    // Verify it...
    if (!self.ctx.Utils.verifyRequestPubKey(txp.proposalSignaturePubKey, txp.proposalSignaturePubKeySig, creatorKeys.xPubKey)) {
      return false;
    }

    creatorSigningPubKey = txp.proposalSignaturePubKey;
  } else {
    creatorSigningPubKey = creatorKeys.requestPubKey || creatorKeys.requestPubKeys[0].key;
  }
  if (!creatorSigningPubKey) {
    return false;
  }

  var hash;
  if (parseInt(txp.version) >= 3) {
    var t = self.walletClient.buildTx(txp);
    hash = t.uncheckedSerialize();
  } else {
    throw new Error('Transaction proposal not supported');
  }

  self.log.debug('Regenerating & verifying tx proposal hash -> Hash: ', hash, ' signature: ', txp.proposalSignature);
  if (!self.ctx.Utils.verifyMessage(hash, txp.proposalSignature, creatorSigningPubKey)) {
    return false;
  }

  if (!self.checkAddress(txp.changeAddress)) {
    return false;
  }

  return true;
};

Verifier.prototype.checkPaypro = function(txp, payproOpts) {
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
Verifier.prototype.checkTxProposal = function(credentials, txp, opts) {
  var self = this;
  opts = opts || {};

  if (!self.checkTxProposalSignature(credentials, txp)) {
    return false;
  }

  if (opts.paypro && !self.checkPaypro(txp, opts.paypro)) {
    return false;
  }

  return true;
};

module.exports = Verifier;
