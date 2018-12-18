'use strict';

var chai = require('chai');
var sinon = require('sinon');
var should = chai.should();

var btcLib = require('@owstack/btc-lib');

var owsCommon = require('@owstack/ows-common');
var Constants = owsCommon.Constants;
var Hash = owsCommon.Hash;
var Script = btcLib.Script;
var Transaction = btcLib.Transaction;
var lodash = owsCommon.deps.lodash;

var blockchainExplorerMock = {};

blockchainExplorerMock.getUtxos = function(addresses, cb) {
  var selected = lodash.filter(blockchainExplorerMock.utxos, function(utxo) {
    return lodash.includes(addresses, utxo.address);
  });
  return cb(null, selected);
};

blockchainExplorerMock.setUtxo = function(address, amount, m, confirmations) {
  var scriptPubKey;
  switch (address.type) {
    case Constants.SCRIPT_TYPES.P2SH:
      scriptPubKey = address.publicKeys ? Script.buildMultisigOut(address.publicKeys, m).toScriptHashOut() : '';
      break;
    case Constants.SCRIPT_TYPES.P2PKH:
      scriptPubKey = Script.buildPublicKeyHashOut(address.address);
      break;
  }
  should.exist(scriptPubKey);
  blockchainExplorerMock.utxos.push({
    txid: Hash.sha256(new Buffer(Math.random() * 100000)).toString('hex'),
    vout: Math.floor((Math.random() * 10) + 1),
    amount: amount,
    address: address.address,
    scriptPubKey: scriptPubKey.toBuffer().toString('hex'),
    confirmations: lodash.isUndefined(confirmations) ? Math.floor((Math.random() * 100) + 1) : +confirmations,
  });
};

blockchainExplorerMock.broadcast = function(raw, cb) {
  blockchainExplorerMock.lastBroadcasted = raw;
  return cb(null, (new Transaction(raw)).id);
};

blockchainExplorerMock.setHistory = function(txs) {
  blockchainExplorerMock.txHistory = txs;
};

blockchainExplorerMock.getTransaction = function(txid, cb) {
  return cb();
};

blockchainExplorerMock.getTransactions = function(addresses, from, to, cb) {
  var list = [].concat(blockchainExplorerMock.txHistory);
  list = lodash.slice(list, from, to);
  return cb(null, list);
};

blockchainExplorerMock.getAddressActivity = function(address, cb) {
  var activeAddresses = lodash.map(blockchainExplorerMock.utxos || [], 'address');
  return cb(null, lodash.includes(activeAddresses, address));
};

blockchainExplorerMock.setFeeLevels = function(levels) {
  blockchainExplorerMock.feeLevels = levels;
};

blockchainExplorerMock.estimateFee = function(nbBlocks, cb) {
  var levels = {};
  lodash.each(nbBlocks, function(nb) {
    var feePerKb = blockchainExplorerMock.feeLevels[nb];
    levels[nb] = lodash.isNumber(feePerKb) ? feePerKb / 1e8 : -1;
  });

  return cb(null, levels);
};

blockchainExplorerMock.reset = function() {
  blockchainExplorerMock.utxos = [];
  blockchainExplorerMock.txHistory = [];
  blockchainExplorerMock.feeLevels = [];
};

module.exports = blockchainExplorerMock;
