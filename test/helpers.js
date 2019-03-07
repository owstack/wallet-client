'use strict';

var chai = require('chai');
var sinon = require('sinon');
var should = chai.should();

var Client = require('..');
var Service = require('@owstack/wallet-service');
var serviceName = 'BTC';
var WalletClient = Client.currencies[serviceName];

var btcLib = require('@owstack/btc-lib');

var owsCommon = require('@owstack/ows-common');
var async = require('async');
var Constants = owsCommon.Constants;
var Hash = owsCommon.Hash;
var request = require('supertest');
var Script = btcLib.Script;
var tingodb = require('tingodb')({ memStore: true });
var lodash = owsCommon.deps.lodash;
var $ = require('preconditions').singleton();

var helpers = {};

helpers.toSatoshi = function(btc) {
  if (lodash.isArray(btc)) {
    return lodash.map(btc, helpers.toSatoshi);
  } else {
    return parseFloat((btc * 1e8).toPrecision(12));
  }
};

helpers.newClient = function(app) {
  $.checkArgument(app);
  return new WalletClient.API({
    baseUrl: '/ws/api',
    request: request(app)
  });
};

helpers.stubRequest = function(err, res) {
  var request = {
    accept: sinon.stub(),
    set: sinon.stub(),
    query: sinon.stub(),
    send: sinon.stub(),
    timeout: sinon.stub(),
    end: sinon.stub().yields(err, res),
  };
  var reqFactory = lodash.reduce(['get', 'post', 'put', 'delete'], function(mem, verb) {
    mem[verb] = function(url) {
      return request;
    };
    return mem;
  }, {});

  return reqFactory;
};

helpers.newDb = function() {
  this.dbCounter = (this.dbCounter || 0) + 1;
  return new tingodb.Db('./db/test' + this.dbCounter, {});
};

helpers.generateUtxos = function(scriptType, publicKeyRing, path, requiredSignatures, amounts) {
  var amounts = [].concat(amounts);
  var utxos = lodash.map(amounts, function(amount, i) {

    var client = new WalletClient.API();
    var address = client.deriveAddress(scriptType, publicKeyRing, path, requiredSignatures, 'testnet');
    var scriptPubKey;
    switch (scriptType) {
      case Constants.SCRIPT_TYPES.P2SH:
        scriptPubKey = Script.buildMultisigOut(address.publicKeys, requiredSignatures).toScriptHashOut();
        break;
      case Constants.SCRIPT_TYPES.P2PKH:
        scriptPubKey = Script.buildPublicKeyHashOut(address.address);
        break;
    }
    should.exist(scriptPubKey);

    var obj = {
      txid: Hash.sha256(new Buffer(i)).toString('hex'),
      vout: 100,
      satoshis: helpers.toSatoshi(amount),
      scriptPubKey: scriptPubKey.toBuffer().toString('hex'),
      address: address.address,
      path: path,
      publicKeys: address.publicKeys,
    };
    return obj;
  });
  return utxos;
};

helpers.createAndJoinWallet = function(clients, m, n, opts, cb) {
  if (lodash.isFunction(opts)) {
    cb = opts;
    opts = null;
  }

  opts = opts || {};

  clients[0].seedFromRandomWithMnemonic({
    networkName: opts.network || 'testnet'
  });
  clients[0].createWallet('mywallet', 'creator', m, n, {
    networkName: opts.network || 'testnet',
    singleAddress: !!opts.singleAddress,
  }, function(err, secret) {
    should.not.exist(err);

    if (n > 1) {
      should.exist(secret);
    }

    async.series([
      function(next) {
        async.each(lodash.range(1, n), function(i, cb) {
          clients[i].seedFromRandomWithMnemonic({
            networkName: 'testnet'
          });
          clients[i].joinWallet(secret, 'copayer ' + i, {}, cb);
        }, next);
      },
      function(next) {
        async.each(lodash.range(n), function(i, cb) {
          clients[i].openWallet(cb);
        }, next);
      },
    ],
    function(err) {
      should.not.exist(err);
      return cb({
        m: m,
        n: n,
        secret: secret,
      });
    });
  });
};

helpers.tamperResponse = function(clients, method, url, args, tamper, cb) {
  clients = [].concat(clients);
  // Use first client to get a clean response from server
  clients[0]._doRequest(method, url, args, false, function(err, result) {
    should.not.exist(err);
    tamper(result);
    // Return tampered data for every client in the list
    lodash.each(clients, function(client) {
      client._doRequest = sinon.stub().withArgs(method, url).yields(null, result);
    });
    return cb();
  });
};

helpers.createAndPublishTxProposal = function(client, opts, cb) {
  if (!opts.outputs) {
    opts.outputs = [{
      toAddress: opts.toAddress,
      amount: opts.amount,
    }];
  }
  client.createTxProposal(opts, function(err, txp) {
    if (err) return cb(err);
    client.publishTxProposal({
      txp: txp
    }, cb);
  });
};

module.exports = helpers;
