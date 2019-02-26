'use strict';

var chai = require('chai');
chai.config.includeStack = true;
var sinon = require('sinon');
var should = chai.should();

var Client = require('..');
var Service = require('@owstack/wallet-service');
var serviceName = 'BTC';
var WalletClient = Client.currencies[serviceName];
var WalletService = Service[serviceName].WalletService;

var btcLib = require('@owstack/btc-lib');
var payProLib = require('@owstack/payment-protocol-lib');

var owsCommon = require('@owstack/ows-common');
var keyLib = require('@owstack/key-lib');
var Address = btcLib.Address;
var async = require('async');
var blockchainExplorerMock = require('./blockchainexplorermock');
var Constants = owsCommon.Constants;
var Errors = WalletClient.errors;
var ExpressApp = WalletService.ExpressApp;
var Hash = owsCommon.Hash;
var HDPrivateKey = keyLib.HDPrivateKey;
var HDPublicKey = keyLib.HDPublicKey;
var helpers = require('./helpers');
var ImportData = require('./legacyImportData.js');
var log = WalletClient.log;
var PayPro = require('@owstack/payment-protocol-lib');
var PrivateKey = keyLib.PrivateKey;
var Script = btcLib.Script;
var Storage = WalletService.Storage;
var testConfig = require('./testConfig');
var TestData = require('./testdata');
var Transaction = btcLib.Transaction;
var Uuid = require('uuid');
var Utils = WalletClient.Common.Utils;
var lodash = owsCommon.deps.lodash;
var $ = require('preconditions').singleton();

describe('client API', function() {
  var clients, app, sandbox;
  var i = 0;
  
  beforeEach(function(done) {
    var storage = new Storage({}, {
      db: helpers.newDb()
    });

    var expressApp = new ExpressApp(testConfig);
    expressApp.start({
      storage: storage,
      blockchainExplorer: blockchainExplorerMock
    }, function() {
      app = expressApp.app;

      // Generates 5 clients
      clients = lodash.map(lodash.range(5), function(i) {
        return helpers.newClient(app);
      });
      blockchainExplorerMock.reset();
      sandbox = sinon.sandbox.create();

      if (!process.env.WC_SHOW_LOGS) {
        sandbox.stub(log, 'warn');
        sandbox.stub(log, 'info');
        sandbox.stub(log, 'error');
      }
      done();
    });
  });
  
  afterEach(function(done) {
    sandbox.restore();
    done();
  });

  describe('constructor', function() {
    it('should set the log level based on the logLevel option', function() {
      var originalLogLevel = log.level;

      var client = new WalletClient.API({
        logLevel: 'info'
      });
      client.logLevel.should.equal('info');
      log.level.should.equal('info');

      var client = new WalletClient.API({
        logLevel: 'debug'
      });
      client.logLevel.should.equal('debug');
      log.level.should.equal('debug');

      log.level = originalLogLevel; //restore since log is a singleton
    });

    it('should use silent for the log level if no logLevel is specified', function() {
      var originalLogLevel = log.level;

      log.level = 'foo;'

      var client = new WalletClient.API();
      client.logLevel.should.equal('silent');
      log.level.should.equal('silent');

      log.level = originalLogLevel; //restore since log is a singleton
    });
  });

  describe('Client Internals', function() {
    it('should expose network clients', function() {
      should.exist(Client.currencies.BCH);
      should.exist(Client.currencies.BTC);
      should.exist(Client.currencies.LTC);
    });
  });

  describe('Server internals', function() {
    it('should allow cors', function(done) {
      clients[0].credentials = {};
      clients[0]._doRequest('options', '/', {}, false, function(err, x, headers) {
        headers['access-control-allow-origin'].should.equal('*');
        should.exist(headers['access-control-allow-methods']);
        should.exist(headers['access-control-allow-headers']);
        done();
      });
    });

    it('should handle critical errors', function(done) {
      var s = sinon.stub();
      s.storeWallet = sinon.stub().yields('bigerror');
      s.fetchWallet = sinon.stub().yields(null);
      var expressApp = new ExpressApp(testConfig);
      expressApp.start({
        storage: s,
        blockchainExplorer: blockchainExplorerMock
      }, function() {
        var s2 = sinon.stub();
        s2.load = sinon.stub().yields(null);
        var client = helpers.newClient(expressApp.app);
        client.storage = s2;
        client.createWallet('1', '2', 1, 1, {
          networkName: 'testnet'
        },
        function(err) {
          err.should.be.an.instanceOf(Error);
          err.message.should.include('bigerror');
          done();
        });
      });
    });

    it('should handle critical errors (Case2)', function(done) {
      var s = sinon.stub();
      s.storeWallet = sinon.stub().yields({
        code: 501,
        message: 'wow'
      });
      s.fetchWallet = sinon.stub().yields(null);
      var expressApp = new ExpressApp(testConfig);
      expressApp.start({
        storage: s,
        blockchainExplorer: blockchainExplorerMock
      }, function() {
        var s2 = sinon.stub();
        s2.load = sinon.stub().yields(null);
        var client = helpers.newClient(expressApp.app);
        client.storage = s2;
        client.createWallet('1', '2', 1, 1, {
            networkName: 'testnet'
          },
          function(err) {
            err.should.be.an.instanceOf(Error);
            err.message.should.include('wow');
            done();
          });
      });
    });

    it('should handle critical errors (Case3)', function(done) {
      var s = sinon.stub();
      s.storeWallet = sinon.stub().yields({
        code: 404,
        message: 'wow'
      });
      s.fetchWallet = sinon.stub().yields(null);
      var expressApp = new ExpressApp(testConfig);
      expressApp.start({
        storage: s,
        blockchainExplorer: blockchainExplorerMock
      }, function() {
        var s2 = sinon.stub();
        s2.load = sinon.stub().yields(null);
        var client = helpers.newClient(expressApp.app);
        client.storage = s2;
        client.createWallet('1', '2', 1, 1, {
            networkName: 'testnet'
          },
          function(err) {
            err.should.be.an.instanceOf(Errors.NOT_FOUND);
            done();
          });
      });
    });

    it('should handle critical errors (Case4)', function(done) {
      var body = {
        code: 999,
        message: 'unexpected body'
      };
      var ret = WalletClient.API._parseError(body);
      ret.should.be.an.instanceOf(Error);
      ret.message.should.equal('999: unexpected body');
      done();
    });

    it('should handle critical errors (Case5)', function(done) {
      clients[0].request = helpers.stubRequest('some error');
      clients[0].createWallet('mywallet', 'creator', 1, 2, {
        networkName: 'testnet'
      }, function(err, secret) {
        should.exist(err);
        err.should.be.an.instanceOf(Errors.CONNECTION_ERROR);
        done();
      });
    });

    it('should correctly use remote message', function(done) {
      var body = {
        code: 'INSUFFICIENT_FUNDS',
      };
      var ret = WalletClient.API._parseError(body);
      ret.should.be.an.instanceOf(Error);
      ret.message.should.equal('Insufficient funds.');

      var body = {
        code: 'INSUFFICIENT_FUNDS',
        message: 'remote message',
      };
      var ret = WalletClient.API._parseError(body);
      ret.should.be.an.instanceOf(Error);
      ret.message.should.equal('remote message');

      var body = {
        code: 'MADE_UP_ERROR',
        message: 'remote message',
      };
      var ret = WalletClient.API._parseError(body);
      ret.should.be.an.instanceOf(Error);
      ret.message.should.equal('MADE_UP_ERROR: remote message');
      done();
    });
  });

  describe('Build & sign txs', function() {
    var masterPrivateKey = 'tprv8ZgxMBicQKsPd8U9aBBJ5J2v8XMwKwZvf8qcu2gLK5FRrsrPeSgkEcNHqKx4zwv6cP536m68q2UD7wVM24zdSCpaJRmpowaeJTeVMXL5v5k';
    var derivedPrivateKey = {
      'BIP44': new HDPrivateKey(masterPrivateKey).deriveChild("m/44'/1'/0'").toString(),
      'BIP45': new HDPrivateKey(masterPrivateKey).deriveChild("m/45'").toString(),
      'BIP48': new HDPrivateKey(masterPrivateKey).deriveChild("m/48'/1'/0'").toString(),
    };

    describe('#buildTx', function() {
      it('Raw tx roundtrip', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1000, 2000]);
        var txp = {
          version: '2.0.0',
          inputs: utxos,
          toAddress: toAddress,
          amount: 1200,
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1],
          fee: 10050,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        var t = new WalletClient.API().getRawTx(txp);
        should.exist(t);
        lodash.isString(t).should.be.true;
        /^[\da-f]+$/.test(t).should.be.true;

        var t2 = new Transaction(t);
        t2.inputs.length.should.equal(2);
        t2.outputs.length.should.equal(2);
        t2.outputs[0].satoshis.should.equal(1200);
      });

      it('should build a tx correctly (BIP44)', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1000, 2000]);
        var txp = {
          version: '2.0.0',
          inputs: utxos,
          toAddress: toAddress,
          amount: 1200,
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1],
          fee: 10050,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        var t = new WalletClient.API().buildTx(txp);
        var btcError = t.getSerializationError({
          disableIsFullySigned: true,
          disableSmallFees: true,
          disableLargeFees: true,
        });

        should.not.exist(btcError);
        t.getFee().should.equal(10050);
      });

      it('should build a tx correctly (BIP48)', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP48']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1000, 2000]);
        var txp = {
          version: '2.0.0',
          inputs: utxos,
          toAddress: toAddress,
          amount: 1200,
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1],
          fee: 10050,
          derivationStrategy: 'BIP48',
          addressType: 'P2PKH',
        };
        var t = new WalletClient.API().buildTx(txp);
        var btcError = t.getSerializationError({
          disableIsFullySigned: true,
          disableSmallFees: true,
          disableLargeFees: true,
        });

        should.not.exist(btcError);
        t.getFee().should.equal(10050);
      });

      it('should protect from creating excessive fee', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1, 2]);
        var txp = {
          inputs: utxos,
          toAddress: toAddress,
          amount: 1.5e8,
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1],
          fee: 1.2e8,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };

        var x = Utils.newBtcTransaction;

        Utils.newBtcTransaction = function() {
          return {
            from: sinon.stub(),
            to: sinon.stub(),
            change: sinon.stub(),
            outputs: [{
              satoshis: 1000,
            }],
            fee: sinon.stub(),
          }
        };

        (function() {
          var t = new WalletClient.API().buildTx(txp);
        }).should.throw('Illegal State');

        Utils.newBtcTransaction = x;
      });

      it('should build a tx with multiple outputs', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1000, 2000]);
        var txp = {
          inputs: utxos,
          outputs: [{
            toAddress: toAddress,
            amount: 800,
            message: 'first output'
          }, {
            toAddress: toAddress,
            amount: 900,
            message: 'second output'
          }],
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1, 2],
          fee: 10000,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        var t = new WalletClient.API().buildTx(txp);
        var btcError = t.getSerializationError({
          disableIsFullySigned: true,
        });
        should.not.exist(btcError);
      });

      it('should build a tx with provided output scripts', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [0.001]);
        var txp = {
          inputs: utxos,
          type: 'external',
          outputs: [{
            "toAddress": "18433T2TSgajt9jWhcTBw4GoNREA6LpX3E",
            "amount": 700,
            "script": "512103ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff210314a96cd6f5a20826070173fe5b7e9797f21fc8ca4a55bcb2d2bde99f55dd352352ae"
          }, {
            "amount": 600,
            "script": "76a9144d5bd54809f846dc6b1a14cbdd0ac87a3c66f76688ac"
          }, {
            "amount": 0,
            "script": "6a1e43430102fa9213bc243af03857d0f9165e971153586d3915201201201210"
          }],
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1, 2, 3],
          fee: 10000,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        var t = new WalletClient.API().buildTx(txp);
        var btcError = t.getSerializationError({
          disableIsFullySigned: true,
        });
        should.not.exist(btcError);
        t.outputs.length.should.equal(4);
        t.outputs[0].script.toHex().should.equal(txp.outputs[0].script);
        t.outputs[0].satoshis.should.equal(txp.outputs[0].amount);
        t.outputs[1].script.toHex().should.equal(txp.outputs[1].script);
        t.outputs[1].satoshis.should.equal(txp.outputs[1].amount);
        t.outputs[2].script.toHex().should.equal(txp.outputs[2].script);
        t.outputs[2].satoshis.should.equal(txp.outputs[2].amount);
        var changeScript = Script.fromAddress(txp.changeAddress.address).toHex();
        t.outputs[3].script.toHex().should.equal(changeScript);
      });

      it('should fail if provided output has no either toAddress or script', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [0.001]);
        var txp = {
          inputs: utxos,
          type: 'external',
          outputs: [{
            "amount": 700,
          }, {
            "amount": 600,
            "script": "76a9144d5bd54809f846dc6b1a14cbdd0ac87a3c66f76688ac"
          }, {
            "amount": 0,
            "script": "6a1e43430102fa9213bc243af03857d0f9165e971153586d3915201201201210"
          }],
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1, 2, 3],
          fee: 10000,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        (function() {
          var t = new WalletClient.API().buildTx(txp);
        }).should.throw('Output should have either toAddress or script specified');

        txp.outputs[0].toAddress = "18433T2TSgajt9jWhcTBw4GoNREA6LpX3E";
        var t = new WalletClient.API().buildTx(txp);
        var btcError = t.getSerializationError({
          disableIsFullySigned: true,
        });
        should.not.exist(btcError);

        delete txp.outputs[0].toAddress;
        txp.outputs[0].script = "512103ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff210314a96cd6f5a20826070173fe5b7e9797f21fc8ca4a55bcb2d2bde99f55dd352352ae";
        t = new WalletClient.API().buildTx(txp);
        var btcError = t.getSerializationError({
          disableIsFullySigned: true,
        });
        should.not.exist(btcError);
      });

      it('should build a v1 tx proposal', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1000, 2000]);
        var txp = {
          version: 3,
          inputs: utxos,
          outputs: [{
            toAddress: toAddress,
            amount: 800,
            message: 'first output'
          }, {
            toAddress: toAddress,
            amount: 900,
            message: 'second output'
          }],
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1, 2],
          fee: 10000,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        var t = new WalletClient.API().buildTx(txp);
        var btcError = t.getSerializationError({
          disableIsFullySigned: true,
        });
        should.not.exist(btcError);
      });
    });

    describe('#signTxp', function() {
      it('should sign BIP45 P2SH correctly', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP45']),
        }];

        var utxos = helpers.generateUtxos('P2SH', publicKeyRing, 'm/2147483647/0/0', 1, [1000, 2000]);
        var txp = {
          inputs: utxos,
          toAddress: toAddress,
          amount: 1200,
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1],
          fee: 10000,
          derivationStrategy: 'BIP45',
          addressType: 'P2SH',
        };
        var signatures = new WalletClient.API().signTxp(txp, derivedPrivateKey['BIP45']);
        signatures.length.should.be.equal(utxos.length);
      });

      it('should sign BIP44 P2PKH correctly', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1000, 2000]);
        var txp = {
          inputs: utxos,
          toAddress: toAddress,
          amount: 1200,
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1],
          fee: 10000,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        var signatures = new WalletClient.API().signTxp(txp, derivedPrivateKey['BIP44']);
        signatures.length.should.be.equal(utxos.length);
      });

      it('should sign multiple-outputs proposal correctly', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1000, 2000]);
        var txp = {
          inputs: utxos,
          outputs: [{
            toAddress: toAddress,
            amount: 800,
            message: 'first output'
          }, {
            toAddress: toAddress,
            amount: 900,
            message: 'second output'
          }],
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1, 2],
          fee: 10000,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        var signatures = new WalletClient.API().signTxp(txp, derivedPrivateKey['BIP44']);
        signatures.length.should.be.equal(utxos.length);
      });

      it('should sign proposal with provided output scripts correctly', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [0.001]);
        var txp = {
          inputs: utxos,
          type: 'external',
          outputs: [{
            "amount": 700,
            "script": "512103ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff210314a96cd6f5a20826070173fe5b7e9797f21fc8ca4a55bcb2d2bde99f55dd352352ae"
          }, {
            "amount": 600,
            "script": "76a9144d5bd54809f846dc6b1a14cbdd0ac87a3c66f76688ac"
          }, {
            "amount": 0,
            "script": "6a1e43430102fa9213bc243af03857d0f9165e971153586d3915201201201210"
          }],
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1, 2, 3],
          fee: 10000,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        var signatures = new WalletClient.API().signTxp(txp, derivedPrivateKey['BIP44']);
        signatures.length.should.be.equal(utxos.length);
      });

      it('should sign v1 proposal correctly', function() {
        var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
        var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

        var publicKeyRing = [{
          xPubKey: new HDPublicKey(derivedPrivateKey['BIP44']),
        }];

        var utxos = helpers.generateUtxos('P2PKH', publicKeyRing, 'm/1/0', 1, [1000, 2000]);
        var txp = {
          version: 3,
          inputs: utxos,
          outputs: [{
            toAddress: toAddress,
            amount: 800,
            message: 'first output'
          }, {
            toAddress: toAddress,
            amount: 900,
            message: 'second output'
          }],
          changeAddress: {
            address: changeAddress
          },
          requiredSignatures: 1,
          outputOrder: [0, 1, 2],
          fee: 10000,
          derivationStrategy: 'BIP44',
          addressType: 'P2PKH',
        };
        var signatures = new WalletClient.API().signTxp(txp, derivedPrivateKey['BIP44']);
        signatures.length.should.be.equal(utxos.length);
      });
    });
  });

  describe('Wallet secret round trip', function() {
    it('should create secret and parse secret', function() {
      var i = 0;
      while (i++ < 100) {
        var walletId = Uuid.v4();
        var networkName = i % 2 == 0 ? 'testnet' : 'btc';
        var privKey = new PrivateKey(null, networkName);
        var client = new WalletClient.API();
        var secret = client._buildSecret(walletId, privKey, networkName);
        var result = client.parseSecret(secret);
        result.walletId.should.equal(walletId);
        result.privKey.toString().should.equal(privKey.toString());
        result.networkName.should.equal(networkName);
      };
    });

    it('should fail on invalid secret', function() {
      (function() {
        new WalletClient.API().parseSecret('invalidSecret');
      }).should.throw('Invalid secret');
    });

    it('should create secret and parse secret from string ', function() {
      var client = new WalletClient.API();
      var walletId = Uuid.v4();
      var networkName = 'testnet';
      var privKey = new PrivateKey(null, networkName);
      var secret = client._buildSecret(walletId, privKey.toString(), networkName);
      var result = client.parseSecret(secret);
      result.walletId.should.equal(walletId);
      result.privKey.toString().should.equal(privKey.toString());
      result.networkName.should.equal(networkName);
    });
  });

  describe('Notification polling', function() {
    var clock, interval;

    beforeEach(function() {
      clock = sinon.useFakeTimers(1234000, 'Date');
    });
    
    afterEach(function() {
      clock.restore();
    });

    it('should fetch notifications at intervals', function(done) {
      helpers.createAndJoinWallet(clients, 2, 2, function() {
        clients[0].on('notification', function(data) {
          notifications.push(data);
        });

        var notifications = [];
        clients[0]._fetchLatestNotifications(5, function() {
          lodash.map(notifications, 'type').should.deep.equal(['NewCopayer', 'WalletComplete']);
          clock.tick(2000);
          notifications = [];
          clients[0]._fetchLatestNotifications(5, function() {
            notifications.length.should.equal(0);
            clock.tick(2000);
            clients[1].createAddress({}, function(err, x) {
              should.not.exist(err);
              clients[0]._fetchLatestNotifications(5, function() {
                lodash.map(notifications, 'type').should.deep.equal(['NewAddress']);
                clock.tick(2000);
                notifications = [];
                clients[0]._fetchLatestNotifications(5, function() {
                  notifications.length.should.equal(0);
                  clients[1].createAddress({}, function(err, x) {
                    should.not.exist(err);
                    clock.tick(60 * 1000);
                    clients[0]._fetchLatestNotifications(5, function() {
                      notifications.length.should.equal(0);
                      done();
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  });

  describe('Wallet Creation', function() {   
    it('should fail to create wallet in bogus device', function(done) {
      clients[0].seedFromRandomWithMnemonic();
      clients[0].keyDerivationOk = false;
      clients[0].createWallet('mywallet', 'pepe', 1, 1, {}, function(err, secret) {
        should.exist(err);
        should.not.exist(secret);
        done();
      });
    });

    it('should encrypt wallet name', function(done) {
      var spy = sinon.spy(clients[0], '_doPostRequest');
      clients[0].seedFromRandomWithMnemonic();
      clients[0].createWallet('mywallet', 'pepe', 1, 1, {}, function(err, secret) {
        should.not.exist(err);
        var url = spy.getCall(0).args[0];
        var body = JSON.stringify(spy.getCall(0).args[1]);
        url.should.contain('/wallets');
        body.should.not.contain('mywallet');
        clients[0].getStatus({}, function(err, status) {
          should.not.exist(err);
          status.wallet.name.should.equal('mywallet');
          done();
        })
      });
    });

    it('should encrypt copayer name in wallet creation', function(done) {
      var spy = sinon.spy(clients[0], '_doPostRequest');
      clients[0].seedFromRandomWithMnemonic();
      clients[0].createWallet('mywallet', 'pepe', 1, 1, {}, function(err, secret) {
        should.not.exist(err);
        var url = spy.getCall(1).args[0];
        var body = JSON.stringify(spy.getCall(1).args[1]);
        url.should.contain('/copayers');
        body.should.not.contain('pepe');
        clients[0].getStatus({}, function(err, status) {
          should.not.exist(err);
          status.wallet.copayers[0].name.should.equal('pepe');
          done();
        })
      });
    });

    it('should be able to access wallet name in non-encrypted wallet (legacy)', function(done) {
      clients[0].seedFromRandomWithMnemonic();
      var pk = new PrivateKey();
      var args = {
        name: 'mywallet',
        m: 1,
        n: 1,
        pubKey: pk.toPublicKey().toString(),
        networkName: 'btc',
        id: '123',
      };
      clients[0]._doPostRequest('/v1/wallets/', args, function(err, wallet) {
        should.not.exist(err);
        var c = clients[0].credentials;

        var args = {
          walletId: '123',
          name: 'pepe',
          xPubKey: c.xPubKey,
          requestPubKey: c.requestPubKey,
          customData: Utils.encryptMessage(JSON.stringify({
            privKey: pk.toString(),
          }), c.personalEncryptingKey),
        };
        var hash = Utils.getCopayerHash(args.name, args.xPubKey, args.requestPubKey);
        args.copayerSignature = Utils.signMessage(hash, pk);
        clients[0]._doPostRequest('/v1/wallets/123/copayers', args, function(err, wallet) {
          should.not.exist(err);
          clients[0].openWallet(function(err) {
            should.not.exist(err);
            clients[0].getStatus({}, function(err, status) {
              should.not.exist(err);
              var wallet = status.wallet;
              wallet.name.should.equal('mywallet');
              should.not.exist(wallet.encryptedName);
              wallet.copayers[0].name.should.equal('pepe');
              should.not.exist(wallet.copayers[0].encryptedName);
              done();
            });
          });
        });
      });
    });

    it('should check balance in a 1-1 ', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        clients[0].getBalance({}, function(err, balance) {
          should.not.exist(err);
          balance.totalAmount.should.equal(0);
          balance.availableAmount.should.equal(0);
          balance.lockedAmount.should.equal(0);
          done();
        })
      });
    });

    it('should be able to complete wallet in copayer that joined later', function(done) {
      helpers.createAndJoinWallet(clients, 2, 3, function() {
        clients[0].getBalance({}, function(err, x) {
          should.not.exist(err);
          clients[1].getBalance({}, function(err, x) {
            should.not.exist(err);
            clients[2].getBalance({}, function(err, x) {
              should.not.exist(err);
              done();
            })
          })
        })
      });
    });

    it('should fire event when wallet is complete', function(done) {
      var checks = 0;
      clients[0].on('walletCompleted', function(wallet) {
        wallet.name.should.equal('mywallet');
        wallet.status.should.equal('complete');
        clients[0].isComplete().should.equal(true);
        if (++checks == 2) done();
      });
      clients[0].createWallet('mywallet', 'creator', 2, 2, {
        networkName: 'testnet'
      }, function(err, secret) {
        should.not.exist(err);
        clients[0].isComplete().should.equal(false);
        clients[1].joinWallet(secret, 'guest', {}, function(err, wallet) {
          should.not.exist(err);
          wallet.name.should.equal('mywallet');
          clients[0].openWallet(function(err, walletStatus) {
            should.not.exist(err);
            should.exist(walletStatus);
            lodash.difference(lodash.map(walletStatus.copayers, 'name'), ['creator', 'guest']).length.should.equal(0);
            if (++checks == 2) done();
          });
        });
      });
    });

    it('should fill wallet info in an incomplete wallet', function(done) {
      clients[0].seedFromRandomWithMnemonic();
      clients[0].createWallet('XXX', 'creator', 2, 3, {}, function(err, secret) {
        should.not.exist(err);
        clients[1].seedFromMnemonic(clients[0].getMnemonic());
        clients[1].openWallet(function(err) {
          clients[1].credentials.walletName.should.equal('XXX');
          clients[1].credentials.m.should.equal(2);
          clients[1].credentials.n.should.equal(3);
          should.not.exist(err);
          done();
        });
      });
    });

    it('should return wallet on successful join', function(done) {
      clients[0].createWallet('mywallet', 'creator', 2, 2, {
        networkName: 'testnet'
      }, function(err, secret) {
        should.not.exist(err);
        clients[1].joinWallet(secret, 'guest', {}, function(err, wallet) {
          should.not.exist(err);
          wallet.name.should.equal('mywallet');
          wallet.copayers[0].name.should.equal('creator');
          wallet.copayers[1].name.should.equal('guest');
          done();
        });
      });
    });

    it('should not allow to join wallet on bogus device', function(done) {
      clients[0].createWallet('mywallet', 'creator', 2, 2, {
        networkName: 'testnet'
      }, function(err, secret) {
        should.not.exist(err);
        clients[1].keyDerivationOk = false;
        clients[1].joinWallet(secret, 'guest', {}, function(err, wallet) {
          should.exist(err);
          done();
        });
      });
    });

    it('should not allow to join a full wallet ', function(done) {
      helpers.createAndJoinWallet(clients, 2, 2, function(w) {
        should.exist(w.secret);
        clients[4].joinWallet(w.secret, 'copayer', {}, function(err, result) {
          err.should.be.an.instanceOf(Errors.WALLET_FULL);
          done();
        });
      });
    });

    it('should fail with an invalid secret', function(done) {
      // Invalid
      clients[0].joinWallet('dummy', 'copayer', {}, function(err, result) {
        err.message.should.contain('Invalid secret');
        // Right length, invalid char for base 58
        clients[0].joinWallet('DsZbqNQQ9LrTKU8EknR7gFKyCQMPg2UUHNPZ1BzM5EbJwjRZaUNBfNtdWLluuFc0f7f7sTCkh7T', 'copayer', {}, function(err, result) {
          err.message.should.contain('Invalid secret');
          done();
        });
      });
    });

    it('should fail with an unknown secret', function(done) {
      // Unknown walletId
      var oldSecret = '3bJKRn1HkQTpwhVaJMaJ22KwsjN24ML9uKfkSrP7iDuq91vSsTEygfGMMpo6kWLp1pXG9wZSKcT';
      clients[0].joinWallet(oldSecret, 'copayer', {}, function(err, result) {
        err.message.should.contain('Invalid secret');
        done();
      });
    });

    it('should detect wallets with bad signatures', function(done) {
      // Do not complete clients[1] pkr
      var openWalletStub = sinon.stub(clients[1], 'openWallet').yields();

      helpers.createAndJoinWallet(clients, 2, 3, function() {
        helpers.tamperResponse([clients[0], clients[1]], 'get', '/v1/wallets/', {}, function(status) {
          status.wallet.copayers[0].xPubKey = status.wallet.copayers[1].xPubKey;
        }, function() {
          openWalletStub.restore();
          clients[1].openWallet(function(err, x) {
            err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
            done();
          });
        });
      });
    });

    it('should detect wallets with missing signatures', function(done) {
      // Do not complete clients[1] pkr
      var openWalletStub = sinon.stub(clients[1], 'openWallet').yields();

      helpers.createAndJoinWallet(clients, 2, 3, function() {
        helpers.tamperResponse([clients[0], clients[1]], 'get', '/v1/wallets/', {}, function(status) {
          delete status.wallet.copayers[1].xPubKey;
        }, function() {
          openWalletStub.restore();
          clients[1].openWallet(function(err, x) {
            err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
            done();
          });
        });
      });
    });

    it('should detect wallets missing callers pubkey', function(done) {
      // Do not complete clients[1] pkr
      var openWalletStub = sinon.stub(clients[1], 'openWallet').yields();

      helpers.createAndJoinWallet(clients, 2, 3, function() {
        helpers.tamperResponse([clients[0], clients[1]], 'get', '/v1/wallets/', {}, function(status) {
          // Replace caller's pubkey
          status.wallet.copayers[1].xPubKey = (new HDPrivateKey()).publicKey;
          // Add a correct signature
          status.wallet.copayers[1].xPubKeySignature = Utils.signMessage(
            status.wallet.copayers[1].xPubKey.toString(),
            clients[0].credentials.privKey
          );
        }, function() {
          openWalletStub.restore();
          clients[1].openWallet(function(err, x) {
            err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
            done();
          });
        });
      });
    });

    it('should perform a dry join without actually joining', function(done) {
      clients[0].createWallet('mywallet', 'creator', 1, 2, {}, function(err, secret) {
        should.not.exist(err);
        should.exist(secret);
        clients[1].joinWallet(secret, 'dummy', {
          dryRun: true
        }, function(err, wallet) {
          should.not.exist(err);
          should.exist(wallet);
          wallet.status.should.equal('pending');
          wallet.copayers.length.should.equal(1);
          done();
        });
      });
    });

    it('should return wallet status even if wallet is not yet complete', function(done) {
      clients[0].createWallet('mywallet', 'creator', 1, 2, {
        networkName: 'testnet'
      }, function(err, secret) {
        should.not.exist(err);
        should.exist(secret);

        clients[0].getStatus({}, function(err, status) {
          should.not.exist(err);
          should.exist(status);
          status.wallet.status.should.equal('pending');
          should.exist(status.wallet.secret);
          status.wallet.secret.should.equal(secret);
          done();
        });
      });
    });

    it('should return status using v1 version', function(done) {
      clients[0].createWallet('mywallet', 'creator', 1, 1, {
        networkName: 'testnet'
      }, function(err, secret) {
        should.not.exist(err);
        clients[0].getStatus({}, function(err, status) {
          should.not.exist(err);
          should.not.exist(status.wallet.publicKeyRing);
          status.wallet.status.should.equal('complete');
          done();
        });
      });
    });

    it('should return extended status using v1 version', function(done) {
      clients[0].createWallet('mywallet', 'creator', 1, 1, {
        networkName: 'testnet'
      }, function(err, secret) {
        should.not.exist(err);
        clients[0].getStatus({
          includeExtendedInfo: true
        }, function(err, status) {
          should.not.exist(err);
          status.wallet.publicKeyRing.length.should.equal(1);
          status.wallet.status.should.equal('complete');
          done();
        });
      });
    });

    it('should store wallet privKey', function(done) {
      clients[0].createWallet('mywallet', 'creator', 1, 1, {
        networkName: 'testnet'
      }, function(err) {

        var key = clients[0].credentials.privKey;
        should.not.exist(err);
        clients[0].getStatus({
          includeExtendedInfo: true
        }, function(err, status) {
          should.not.exist(err);
          status.wallet.publicKeyRing.length.should.equal(1);
          status.wallet.status.should.equal('complete');
          var key2 = status.customData.privKey;
          key2.should.be.equal(key2);
          done();
        });
      });
    });

    it('should set wallet privKey from wallet service', function(done) {
      clients[0].createWallet('mywallet', 'creator', 1, 1, {
        networkName: 'testnet'
      }, function(err) {

        var pkey = clients[0].credentials.privKey;
        var skey = clients[0].credentials.sharedEncryptingKey;
        delete clients[0].credentials.privKey;
        delete clients[0].credentials.sharedEncryptingKey;
        should.not.exist(err);
        clients[0].getStatus({
          includeExtendedInfo: true
        }, function(err, status) {
          should.not.exist(err);
          clients[0].credentials.privKey.should.equal(pkey);
          clients[0].credentials.sharedEncryptingKey.should.equal(skey);
          done();
        });
      });
    });

    it('should prepare wallet with external xpubkey', function(done) {
      var client = helpers.newClient(app);
      client.seedFromExtendedPublicKey(
        'xpub661MyMwAqRbcGVyYUcHbZi9KNhN9Tdj8qHi9ZdoUXP1VeKiXDGGrE9tSoJKYhGFE2rimteYdwvoP6e87zS5LsgcEvsvdrpPBEmeWz9EeAUq',
        'ledger', 
        '1a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f00', {
          account: 1,
          derivationStrategy: 'BIP48',
        });
      client.isPrivKeyExternal().should.equal(true);
      client.credentials.account.should.equal(1);
      client.credentials.derivationStrategy.should.equal('BIP48');
      client.credentials.requestPrivKey.should.equal('36a4504f0c6651db30484c2c128304a7ea548ef5935f19ed6af99db8000c75a4');
      client.credentials.personalEncryptingKey.should.equal('wYI1597BfOv06NI6Uye3tA==');
      client.getPrivKeyExternalSourceName().should.equal('ledger');
      done();
    });

    it('should create a 1-1 wallet with random mnemonic', function(done) {
      clients[0].seedFromRandomWithMnemonic();
      clients[0].createWallet('mywallet', 'creator', 1, 1, {
          networkName: 'btc'
        },
        function(err) {
          should.not.exist(err);
          clients[0].openWallet(function(err) {
            should.not.exist(err);
            should.not.exist(err);
            clients[0].credentials.networkName.should.equal('btc');
            clients[0].getMnemonic().split(' ').length.should.equal(12);
            done();
          });
        });
    });

    it('should create a 1-1 wallet with given mnemonic', function(done) {
      var words = 'forget announce travel fury farm alpha chaos choice talent sting eagle supreme';
      clients[0].seedFromMnemonic(words);
      clients[0].createWallet('mywallet', 'creator', 1, 1, {
          networkName: 'btc',
          derivationStrategy: 'BIP48',
        },
        function(err) {
          should.not.exist(err);
          clients[0].openWallet(function(err) {
            should.not.exist(err);
            should.exist(clients[0].getMnemonic());
            words.should.be.equal(clients[0].getMnemonic());
            clients[0].credentials.xPrivKey.should.equal('xprv9s21ZrQH143K4X2frJxRmGsmef9UfXhmfL4hdTGLm5ruSX46gekuSTspJX63d5nEi9q2wqUgg4KZ4yhSPy13CzVezAH6t6gCox1DN2hXV3L')
            done();
          });
        });
    });

    it('should create a 2-3 wallet with given mnemonic', function(done) {
      var words = 'forget announce travel fury farm alpha chaos choice talent sting eagle supreme';
      clients[0].seedFromMnemonic(words);
      clients[0].createWallet('mywallet', 'creator', 2, 3, {
          networkName: 'btc'
        },
        function(err, secret) {
          should.not.exist(err);
          should.exist(secret);
          clients[0].openWallet(function(err) {
            should.not.exist(err);
            should.exist(clients[0].getMnemonic());
            words.should.be.equal(clients[0].getMnemonic());
            clients[0].credentials.xPrivKey.should.equal('xprv9s21ZrQH143K4X2frJxRmGsmef9UfXhmfL4hdTGLm5ruSX46gekuSTspJX63d5nEi9q2wqUgg4KZ4yhSPy13CzVezAH6t6gCox1DN2hXV3L')
            done();
          });
        });
    });
  });

  describe('#getMainAddresses', function() {
    beforeEach(function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          clients[0].createAddress({}, function(err, x0) {
            should.not.exist(err);
            blockchainExplorerMock.setUtxo(x0, 1, 1);
            done();
          });
        });
      });
    });

    it('Should return all main addresses', function(done) {
      clients[0].getMainAddresses({
        doNotVerify: true
      }, function(err, addr) {
        should.not.exist(err);
        addr.length.should.equal(2);
        done();
      });
    });

    it('Should return only main addresses when change addresses exist', function(done) {
      var opts = {
        amount: 0.1e8,
        toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
        message: 'hello 1-1',
      };
      helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {        
        should.not.exist(err);
        clients[0].getMainAddresses({}, function(err, addr) {
          should.not.exist(err);
          addr.length.should.equal(2);
          done();
        });
      });
    });
  });

  describe('#getUtxos', function() {
    beforeEach(function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function(w) {
        done();
      });
    });

    it('Should return UTXOs', function(done) {
      clients[0].getUtxos({}, function(err, utxos) {
        should.not.exist(err);
        utxos.length.should.equal(0);
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          blockchainExplorerMock.setUtxo(x0, 1, 1);
          clients[0].getUtxos({}, function(err, utxos) {
            should.not.exist(err);
            utxos.length.should.equal(1);
            done();
          });
        });
      });
    });

    it('Should return UTXOs for specific addresses', function(done) {
      async.map(lodash.range(3), function(i, next) {
        clients[0].createAddress({}, function(err, x) {
          should.not.exist(err);
          should.exist(x.address);
          blockchainExplorerMock.setUtxo(x, 1, 1);
          next(null, x.address);
        });
      }, function(err, addresses) {
        var opts = {
          addresses: lodash.take(addresses, 2),
        };
        clients[0].getUtxos(opts, function(err, utxos) {
          should.not.exist(err);
          utxos.length.should.equal(2);
          lodash.sumBy(utxos, 'satoshis').should.equal(2 * 1e8);
          done();
        });
      });
    });
  });

  describe('Network fees', function() {
    it('should get current fee levels', function(done) {
      blockchainExplorerMock.setFeeLevels({
        1: 40000,
        3: 20000,
        10: 18000,
      });
      clients[0].credentials = {};
      clients[0].getFeeLevels('btc', function(err, levels) {
        should.not.exist(err);
        should.exist(levels);
        lodash.difference(['priority', 'normal', 'economy'], lodash.map(levels, 'level')).should.be.empty;
        done();
      });
    });
  });

  describe('Version', function() {
    it('should get version of wallet service', function(done) {
      clients[0].credentials = {};
      clients[0].getVersion(function(err, version) {
        if (err) {
          // if wallet service is older version without getVersion support
          err.should.be.an.instanceOf(Errors.NOT_FOUND);
        } else {
          // if wallet service is up-to-date
          should.exist(version);
          should.exist(version.serviceVersion);
          version.serviceVersion.should.contain('ws-');
        }
        done();
      });
    });
  });

  describe('Preferences', function() {
    it('should save and retrieve preferences', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        clients[0].getPreferences(function(err, preferences) {
          should.not.exist(err);
          preferences.should.be.empty;
          clients[0].savePreferences({
            email: 'dummy@dummy.com'
          }, function(err) {
            should.not.exist(err);
            clients[0].getPreferences(function(err, preferences) {
              should.not.exist(err);
              should.exist(preferences);
              preferences.email.should.equal('dummy@dummy.com');
              done();
            });
          });
        });
      });
    });
  });

  describe('Fiat rates', function() {
    it('should get fiat exchange rate', function(done) {
      var now = Date.now();
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        clients[0].getFiatRate({
          currency: 'BTC',
          code: 'USD',
          ts: now,
        }, function(err, res) {
          should.not.exist(err);
          should.exist(res);
          res.ts.should.equal(now);
          should.not.exist(res.rate);
          done();
        });
      });
    });
  });

  describe('Push notifications', function() {
    it('should do a post request', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        clients[0]._doRequest = sinon.stub().yields(null, {
          statusCode: 200,
        });
        clients[0].pushNotificationsSubscribe(function(err, res) {
          should.not.exist(err);
          should.exist(res);
          res.statusCode.should.be.equal(200);
          done();
        });
      });
    });

    it('should do a delete request', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        clients[0]._doRequest = sinon.stub().yields(null);
        clients[0].pushNotificationsUnsubscribe('123', function(err) {
          should.not.exist(err);
          done();
        });
      });
    });
  });

  describe('Tx confirmations', function() {
    it('should do a post request', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        clients[0]._doRequest = sinon.stub().yields(null, {
          statusCode: 200,
        });
        clients[0].txConfirmationSubscribe({
          txid: '123'
        }, function(err, res) {
          should.not.exist(err);
          should.exist(res);
          res.statusCode.should.be.equal(200);
          done();
        });
      });
    });

    it('should do a delete request', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        clients[0]._doRequest = sinon.stub().yields(null);
        clients[0].txConfirmationUnsubscribe('123', function(err) {
          should.not.exist(err);
          done();
        });
      });
    });
  });

  describe('Get send max information', function() {
    var balance;
    beforeEach(function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        clients[0].createAddress({}, function(err, address) {
          should.not.exist(err);
          should.exist(address.address);
          blockchainExplorerMock.setUtxo(address, 2, 1, 1);
          blockchainExplorerMock.setUtxo(address, 1, 1, 0);
          clients[0].getBalance({}, function(err, bl) {
            should.not.exist(err);
            balance = bl;
            done();
          });
        });
      });
    });

    it('should return send max info', function(done) {
      blockchainExplorerMock.setFeeLevels({
        1: 200e2,
      });
      var opts = {
        feeLevel: 'priority',
        excludeUnconfirmedUtxos: false,
        returnInputs: true
      };
      clients[0].getSendMaxInfo(opts, function(err, result) {
        should.not.exist(err);
        should.exist(result);
        result.inputs.length.should.be.equal(2);
        result.amount.should.be.equal(balance.totalAmount - result.fee);
        result.utxosBelowFee.should.be.equal(0);
        result.amountBelowFee.should.be.equal(0);
        result.utxosAboveMaxSize.should.be.equal(0);
        result.amountAboveMaxSize.should.be.equal(0);
        done();
      });
    });

    it('should return data excluding unconfirmed UTXOs', function(done) {
      var opts = {
        feePerKb: 200,
        excludeUnconfirmedUtxos: true,
        returnInputs: true
      };
      clients[0].getSendMaxInfo(opts, function(err, result) {
        should.not.exist(err);
        result.amount.should.be.equal(balance.availableConfirmedAmount - result.fee);
        done();
      });
    });

    it('should return data including unconfirmed UTXOs', function(done) {
      var opts = {
        feePerKb: 200,
        excludeUnconfirmedUtxos: false,
        returnInputs: true
      };
      clients[0].getSendMaxInfo(opts, function(err, result) {
        should.not.exist(err);
        result.amount.should.be.equal(balance.totalAmount - result.fee);
        done();
      });
    });

    it('should return data without inputs', function(done) {
      var opts = {
        feePerKb: 200,
        excludeUnconfirmedUtxos: true,
        returnInputs: false
      };
      clients[0].getSendMaxInfo(opts, function(err, result) {
        should.not.exist(err);
        result.inputs.length.should.be.equal(0);
        done();
      });
    });

    it('should return data with inputs', function(done) {
      var opts = {
        feePerKb: 200,
        excludeUnconfirmedUtxos: true,
        returnInputs: true
      };
      clients[0].getSendMaxInfo(opts, function(err, result) {
        should.not.exist(err);
        result.inputs.length.should.not.equal(0);
        var totalSatoshis = 0;
        lodash.each(result.inputs, function(i) {
          totalSatoshis = totalSatoshis + i.satoshis;
        });
        result.amount.should.be.equal(totalSatoshis - result.fee);
        done();
      });
    });
  });

  describe('Address Creation', function() {
    it('should be able to create address in 1-of-1 wallet', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        clients[0].createAddress({}, function(err, x) {
          should.not.exist(err);
          should.exist(x.address);
          x.address.charAt(0).should.not.equal('2');
          done();
        });
      });
    });

    it('should fail if key derivation is not ok', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        clients[0].keyDerivationOk = false;
        clients[0].createAddress({}, function(err, address) {
          should.exist(err);
          should.not.exist(address);
          err.message.should.contain('new address');
          done();
        });
      });
    });

    it('should be able to create address in all copayers in a 2-3 wallet', function(done) {
      this.timeout(5000);
      helpers.createAndJoinWallet(clients, 2, 3, function() {
        clients[0].createAddress({}, function(err, x) {
          should.not.exist(err);
          should.exist(x.address);
          x.address.charAt(0).should.equal('2');
          clients[1].createAddress({}, function(err, x) {
            should.not.exist(err);
            should.exist(x.address);
            clients[2].createAddress({}, function(err, x) {
              should.not.exist(err);
              should.exist(x.address);
              done();
            });
          });
        });
      });
    });

    it('should see balance on address created by others', function(done) {
      this.timeout(5000);
      helpers.createAndJoinWallet(clients, 2, 2, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);

          blockchainExplorerMock.setUtxo(x0, 10, w.m);
          clients[0].getBalance({}, function(err, bal0) {
            should.not.exist(err);
            bal0.totalAmount.should.equal(10 * 1e8);
            bal0.lockedAmount.should.equal(0);
            clients[1].getBalance({}, function(err, bal1) {
              bal1.totalAmount.should.equal(10 * 1e8);
              bal1.lockedAmount.should.equal(0);
              done();
            });
          });
        });
      });
    });

    it('should detect fake addresses', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        helpers.tamperResponse(clients[0], 'post', '/v1/addresses/', {}, function(address) {
          address.address = '2N86pNEpREGpwZyHVC5vrNUCbF9nM1Geh4K';
        }, function() {
          clients[0].createAddress({}, function(err, x0) {
            err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
            done();
          });
        });
      });
    });

    it('should detect fake public keys', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        helpers.tamperResponse(clients[0], 'post', '/v1/addresses/', {}, function(address) {
          address.publicKeys = [
            '0322defe0c3eb9fcd8bc01878e6dbca7a6846880908d214b50a752445040cc5c54',
            '02bf3aadc17131ca8144829fa1883c1ac0a8839067af4bca47a90ccae63d0d8037'
          ];
        }, function() {
          clients[0].createAddress({}, function(err, x0) {
            err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
            done();
          });
        });
      });
    });

    it('should be able to derive 25 addresses', function(done) {
      this.timeout(5000);
      var num = 25;
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        function create(callback) {
          clients[0].createAddress({
            ignoreMaxGap: true
          }, function(err, x) {
            should.not.exist(err);
            should.exist(x.address);
            callback(err, x);
          });
        }

        var tasks = [];
        for (var i = 0; i < num; i++) {
          tasks.push(create);
        }

        async.parallel(tasks, function(err, results) {
          should.not.exist(err);
          results.length.should.equal(num);
          done();
        });
      });
    });
  });

  describe('Notifications', function() {
    var clock;
    beforeEach(function(done) {
      this.timeout(5000);
      clock = sinon.useFakeTimers(1234000, 'Date');
      helpers.createAndJoinWallet(clients, 2, 2, function() {
        clock.tick(25 * 1000);
        clients[0].createAddress({}, function(err, x) {
          should.not.exist(err);
          clock.tick(25 * 1000);
          clients[1].createAddress({}, function(err, x) {
            should.not.exist(err);
            done();
          });
        });
      });
    });
    afterEach(function() {
      clock.restore();
    });

    it('should receive notifications', function(done) {
      clients[0].getNotifications({}, function(err, notifications) {
        should.not.exist(err);
        notifications.length.should.equal(3);
        lodash.map(notifications, 'type').should.deep.equal(['NewCopayer', 'WalletComplete', 'NewAddress']);
        clients[0].getNotifications({
          lastNotificationId: lodash.last(notifications).id
        }, function(err, notifications) {
          should.not.exist(err);
          notifications.length.should.equal(0, 'should only return unread notifications');
          done();
        });
      });
    });

    it('should not receive old notifications', function(done) {
      clock.tick(61 * 1000); // more than 60 seconds
      clients[0].getNotifications({}, function(err, notifications) {
        should.not.exist(err);
        notifications.length.should.equal(0);
        done();
      });
    });

    it('should not receive notifications for self generated events unless specified', function(done) {
      clients[0].getNotifications({}, function(err, notifications) {
        should.not.exist(err);
        notifications.length.should.equal(3);
        lodash.map(notifications, 'type').should.deep.equal(['NewCopayer', 'WalletComplete', 'NewAddress']);
        clients[0].getNotifications({
          includeOwn: true,
        }, function(err, notifications) {
          should.not.exist(err);
          notifications.length.should.equal(5);
          lodash.map(notifications, 'type').should.deep.equal(['NewCopayer', 'NewCopayer', 'WalletComplete', 'NewAddress', 'NewAddress']);
          done();
        });
      });
    });
  });

  describe('Transaction Proposals Creation and Locked funds', function() {
    var myAddress;
    beforeEach(function(done) {
      helpers.createAndJoinWallet(clients, 2, 3, function(w) {
        clients[0].createAddress({}, function(err, address) {
          should.not.exist(err);
          myAddress = address;
          blockchainExplorerMock.setUtxo(address, 2, 2);
          blockchainExplorerMock.setUtxo(address, 2, 2);
          blockchainExplorerMock.setUtxo(address, 1, 2, 0);
          done();
        });
      });
    });

    it('Should create & publish proposal', function(done) {
      blockchainExplorerMock.setFeeLevels({
        2: 123e2,
      });
      var toAddress = 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5';
      var opts = {
        outputs: [{
          amount: 1e8,
          toAddress: toAddress,
          message: 'world',
        }, {
          amount: 2e8,
          toAddress: toAddress,
        }],
        message: 'hello',
        customData: {
          someObj: {
            x: 1
          },
          someStr: "str"
        }
      };
      clients[0].createTxProposal(opts, function(err, txp) {
        should.not.exist(err);
        should.exist(txp);

        txp.status.should.equal('temporary');
        txp.message.should.equal('hello');
        txp.outputs.length.should.equal(2);
        lodash.sumBy(txp.outputs, 'amount').should.equal(3e8);
        txp.outputs[0].message.should.equal('world');
        lodash.uniqBy(txp.outputs, 'toAddress').length.should.equal(1);
        lodash.uniq(lodash.map(txp.outputs, 'toAddress'))[0].should.equal(toAddress);
        txp.hasUnconfirmedInputs.should.equal(false);
        txp.feeLevel.should.equal('normal');
        txp.feePerKb.should.equal(123e2);

        should.exist(txp.encryptedMessage);
        should.exist(txp.outputs[0].encryptedMessage);

        clients[0].getTxProposals({}, function(err, txps) {
          should.not.exist(err);
          txps.should.be.empty;

          clients[0].publishTxProposal({
            txp: txp,
          }, function(err, publishedTxp) {
            should.not.exist(err);
            should.exist(publishedTxp);
            publishedTxp.status.should.equal('pending');
            clients[0].getTxProposals({}, function(err, txps) {
              should.not.exist(err);
              txps.length.should.equal(1);
              var x = txps[0];
              x.id.should.equal(txp.id);
              should.exist(x.proposalSignature);
              should.not.exist(x.proposalSignaturePubKey);
              should.not.exist(x.proposalSignaturePubKeySig);
              // Should be visible for other copayers as well
              clients[1].getTxProposals({}, function(err, txps) {
                should.not.exist(err);
                txps.length.should.equal(1);
                txps[0].id.should.equal(txp.id);
                done();
              });
            });
          });
        });
      });
    });

    it('Should create, publish, recreate, republish proposal', function(done) {
      blockchainExplorerMock.setFeeLevels({
        1: 456e2,
        6: 123e2,
      });
      var toAddress = 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5';
      var opts = {
        txProposalId: '1234',
        outputs: [{
          amount: 1e8,
          toAddress: toAddress,
          message: 'world',
        }, {
          amount: 2e8,
          toAddress: toAddress,
        }],
        message: 'hello',
        feeLevel: 'economy',
        customData: {
          someObj: {
            x: 1
          },
          someStr: "str"
        }
      };
      clients[0].createTxProposal(opts, function(err, txp) {
        should.not.exist(err);
        should.exist(txp);
        txp.status.should.equal('temporary');
        txp.feeLevel.should.equal('economy');
        txp.feePerKb.should.equal(123e2);
        clients[0].publishTxProposal({
          txp: txp,
        }, function(err, publishedTxp) {
          should.not.exist(err);
          should.exist(publishedTxp);
          publishedTxp.status.should.equal('pending');
          clients[0].getTxProposals({}, function(err, txps) {
            should.not.exist(err);
            txps.length.should.equal(1);
            // Try to republish from copayer 1
            clients[1].createTxProposal(opts, function(err, txp) {
              should.not.exist(err);
              should.exist(txp);
              txp.status.should.equal('pending');
              clients[1].publishTxProposal({
                txp: txp
              }, function(err, publishedTxp) {
                should.not.exist(err);
                should.exist(publishedTxp);
                publishedTxp.status.should.equal('pending');
                done();
              });
            });
          });
        });
      });
    });

    it('Should protect against tampering at proposal creation', function(done) {
      var opts = {
        outputs: [{
          amount: 1e8,
          toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
          message: 'world'
        }, {
          amount: 2e8,
          toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
        }],
        feePerKb: 123e2,
        changeAddress: myAddress,
        message: 'hello',
      };

      var tamperings = [
        function(txp) {
          txp.feePerKb = 45600;
        },
        function(txp) {
          txp.message = 'dummy';
        },
        function(txp) {
          txp.payProUrl = 'dummy';
        },
        function(txp) {
          txp.customData = 'dummy';
        },
        function(txp) {
          txp.outputs.push(txp.outputs[0]);
        },
        function(txp) {
          txp.outputs[0].toAddress = 'mjfjcbuYwBUdEyq2m7AezjCAR4etUBqyiE';
        },
        function(txp) {
          txp.outputs[0].amount = 2e8;
        },
        function(txp) {
          txp.outputs[1].amount = 3e8;
        },
        function(txp) {
          txp.outputs[0].message = 'dummy';
        },
        function(txp) {
          txp.changeAddress.address = 'mjfjcbuYwBUdEyq2m7AezjCAR4etUBqyiE';
        },
      ];

      var tmp = clients[0]._getCreateTxProposalArgs;
      var args = clients[0]._getCreateTxProposalArgs(opts);
      clients[0]._getCreateTxProposalArgs = function(opts) {
        return args;
      };
      async.each(tamperings, function(tamperFn, next) {
        helpers.tamperResponse(clients[0], 'post', '/v1/txproposals/', args, tamperFn, function() {
          clients[0].createTxProposal(opts, function(err, txp) {
            should.exist(err, tamperFn);
            err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
            next();
          });
        });
      }, function(err) {
        should.not.exist(err);
        clients[0]._getCreateTxProposalArgs = tmp;
        done();
      });
    });

    it('Should fail to publish when not enough available UTXOs', function(done) {
      var opts = {
        outputs: [{
          amount: 3e8,
          toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
        }],
        feePerKb: 100e2,
      };

      var txp1, txp2;
      async.series([

        function(next) {
          clients[0].createTxProposal(opts, function(err, txp) {
            txp1 = txp;
            next(err);
          });
        },
        function(next) {
          clients[0].createTxProposal(opts, function(err, txp) {
            txp2 = txp;
            next(err);
          });

        },
        function(next) {
          clients[0].publishTxProposal({
            txp: txp1
          }, next);
        },
        function(next) {
          clients[0].publishTxProposal({
            txp: txp2
          }, function(err) {
            should.exist(err);
            err.should.be.an.instanceOf(Errors.UNAVAILABLE_UTXOS);
            next();
          });
        },
        function(next) {
          clients[1].rejectTxProposal(txp1, 'Free locked UTXOs', next);
        },
        function(next) {
          clients[2].rejectTxProposal(txp1, 'Free locked UTXOs', next);
        },
        function(next) {
          clients[0].publishTxProposal({
            txp: txp2
          }, next);
        },
      ], function(err) {
        should.not.exist(err);
        done();
      });
    });

    it('Should sign proposal', function(done) {
      var toAddress = 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5';
      var opts = {
        outputs: [{
          amount: 1e8,
          toAddress: toAddress,
        }, {
          amount: 2e8,
          toAddress: toAddress,
        }],
        feePerKb: 100e2,
        message: 'just some message',
      };
      clients[0].createTxProposal(opts, function(err, txp) {
        should.not.exist(err);
        should.exist(txp);
        clients[0].publishTxProposal({
          txp: txp,
        }, function(err, publishedTxp) {
          should.not.exist(err);
          should.exist(publishedTxp);
          publishedTxp.status.should.equal('pending');
          clients[0].signTxProposal(publishedTxp, function(err, txp) {
            should.not.exist(err);
            clients[1].signTxProposal(publishedTxp, function(err, txp) {
              should.not.exist(err);
              txp.status.should.equal('accepted');
              done();
            });
          });
        });
      });
    });

    it('Should create proposal with unconfirmed inputs', function(done) {
      var opts = {
        amount: 4.5e8,
        toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
        message: 'hello',
      };
      helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
        should.not.exist(err);
        clients[0].getTx(x.id, function(err, x2) {
          should.not.exist(err);
          x2.hasUnconfirmedInputs.should.equal(true);
          done();
        });
      });
    });

    it('Should fail to create proposal with insufficient funds', function(done) {
      helpers.createAndJoinWallet(clients, 2, 2, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          blockchainExplorerMock.setUtxo(x0, 1, 2);
          blockchainExplorerMock.setUtxo(x0, 1, 2);
          var opts = {
            amount: 3e8,
            toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
            message: 'hello 1-1',
          };
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
            should.exist(err);
            err.should.be.an.instanceOf(Errors.INSUFFICIENT_FUNDS);
            done();
          });
        });
      });
    });

    it('Should fail to create proposal with insufficient funds for fee', function(done) {
      var opts = {
        amount: 5e8 - 200e2,
        toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
        message: 'hello 1-1',
        feePerKb: 800e2,
      };
      helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
        should.exist(err);
        err.should.be.an.instanceOf(Errors.INSUFFICIENT_FUNDS_FOR_FEE);
        opts.feePerKb = 100e2;
        helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
          should.not.exist(err);
          clients[0].getTx(x.id, function(err, x2) {
            should.not.exist(err);
            should.exist(x2);
            done();
          });
        });
      });
    });

    it('Should lock and release funds through rejection', function(done) {
      var opts = {
        amount: 2.2e8,
        toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
      };
      helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
        should.not.exist(err);

        helpers.createAndPublishTxProposal(clients[0], opts, function(err, y) {
          err.should.be.an.instanceOf(Errors.LOCKED_FUNDS);

          clients[1].rejectTxProposal(x, 'no', function(err) {
            should.not.exist(err);
            clients[2].rejectTxProposal(x, 'no', function(err, z) {
              should.not.exist(err);
              z.status.should.equal('rejected');
              helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
                should.not.exist(err);
                done();
              });
            });
          });
        });
      });
    });

    it('Should lock and release funds through removal', function(done) {
      var opts = {
        amount: 2.2e8,
        toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
        message: 'hello 1-1',
      };
      helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
        should.not.exist(err);

        helpers.createAndPublishTxProposal(clients[0], opts, function(err, y) {
          err.should.be.an.instanceOf(Errors.LOCKED_FUNDS);

          clients[0].removeTxProposal(x, function(err) {
            should.not.exist(err);

            helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
              should.not.exist(err);
              done();
            });
          });
        });
      });
    });

    it('Should keep message and refusal texts', function(done) {
      var opts = {
        amount: 1e8,
        toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
        message: 'some message',
      };
      helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
        should.not.exist(err);
        clients[1].rejectTxProposal(x, 'rejection comment', function(err, tx1) {
          should.not.exist(err);

          clients[2].getTxProposals({}, function(err, txs) {
            should.not.exist(err);
            txs[0].message.should.equal('some message');
            txs[0].actions[0].copayerName.should.equal('copayer 1');
            txs[0].actions[0].comment.should.equal('rejection comment');
            done();
          });
        });
      });
    });

    it('Should encrypt proposal message', function(done) {
      var opts = {
        outputs: [{
          amount: 1000e2,
          toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
        }],
        message: 'some message',
        feePerKb: 100e2,
      };
      var spy = sinon.spy(clients[0], '_doPostRequest');
      clients[0].createTxProposal(opts, function(err, x) {
        should.not.exist(err);
        spy.calledOnce.should.be.true;
        JSON.stringify(spy.getCall(0).args).should.not.contain('some message');
        done();
      });
    });

    it('Should encrypt proposal refusal comment', function(done) {
      var opts = {
        amount: 1e8,
        toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
      };
      helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
        should.not.exist(err);
        var spy = sinon.spy(clients[1], '_doPostRequest');
        clients[1].rejectTxProposal(x, 'rejection comment', function(err, tx1) {
          should.not.exist(err);
          spy.calledOnce.should.be.true;
          JSON.stringify(spy.getCall(0).args).should.not.contain('rejection comment');
          done();
        });
      });
    });

    describe('Detecting tampered tx proposals', function() {
      it('should detect wrong signature', function(done) {
        helpers.createAndJoinWallet(clients, 1, 1, function() {
          clients[0].createAddress({}, function(err, x0) {
            should.not.exist(err);
            blockchainExplorerMock.setUtxo(x0, 10, 1);
            var opts = {
              amount: 1000e2,
              toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
              message: 'hello',
            };
            helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
              should.not.exist(err);

              helpers.tamperResponse(clients[0], 'get', '/v1/txproposals/', {}, function(txps) {
                txps[0].proposalSignature = '304402206e4a1db06e00068582d3be41cfc795dcf702451c132581e661e7241ef34ca19202203e17598b4764913309897d56446b51bc1dcd41a25d90fdb5f87a6b58fe3a6920';
              }, function() {
                clients[0].getTxProposals({}, function(err, txps) {
                  should.exist(err);
                  err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
                  done();
                });
              });
            });
          });
        });
      });

      it('should detect tampered amount', function(done) {
        var opts = {
          amount: 1000e2,
          toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
          message: 'hello',
        };
        helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
          should.not.exist(err);

          helpers.tamperResponse(clients[0], 'get', '/v1/txproposals/', {}, function(txps) {
            txps[0].outputs[0].amount = 1e8;
          }, function() {
            clients[0].getTxProposals({}, function(err, txps) {
              should.exist(err);
              err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
              done();
            });
          });
        });
      });

      it('should detect change address not it wallet', function(done) {
        var opts = {
          amount: 1000e2,
          toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
          message: 'hello',
        };
        helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
          should.not.exist(err);

          helpers.tamperResponse(clients[0], 'get', '/v1/txproposals/', {}, function(txps) {
            txps[0].changeAddress.address = 'mnA11ZwktRp4sZJbS8MbXmmFPZAgriuwhh';
          }, function() {
            clients[0].getTxProposals({}, function(err, txps) {
              should.exist(err);
              err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
              done();
            });
          });
        });
      });
    });
  });

  describe('Transaction Proposal signing', function() {
    this.timeout(5000);
    function setup(m, n, network, cb) {
      helpers.createAndJoinWallet(clients, m, n, {
        networkName: network,
      }, function(w) {
        clients[0].createAddress({}, function(err, address) {
          should.not.exist(err);
          blockchainExplorerMock.setUtxo(address, 2, 2);
          blockchainExplorerMock.setUtxo(address, 2, 2);
          blockchainExplorerMock.setUtxo(address, 1, 2, 0);
          cb();
        });
      });
    };

    beforeEach(function(done) {
      setup(2, 3, 'testnet', done);
    });

    it('Should sign proposal', function(done) {
      var toAddress = 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5';
      var opts = {
        outputs: [{
          amount: 1e8,
          toAddress: toAddress,
        }, {
          amount: 2e8,
          toAddress: toAddress,
        }],
        feePerKb: 100e2,
        message: 'just some message'
      };
      clients[0].createTxProposal(opts, function(err, txp) {
        should.not.exist(err);
        should.exist(txp);
        clients[0].publishTxProposal({
          txp: txp,
        }, function(err, publishedTxp) {
          should.not.exist(err);
          should.exist(publishedTxp);
          publishedTxp.status.should.equal('pending');
          clients[0].signTxProposal(publishedTxp, function(err, txp) {
            should.not.exist(err);
            clients[1].signTxProposal(publishedTxp, function(err, txp) {
              should.not.exist(err);
              txp.status.should.equal('accepted');
              done();
            });
          });
        });
      });
    });

    it('Should sign proposal with no change', function(done) {
      var toAddress = 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5';
      var opts = {
        outputs: [{
          amount: 4e8 - 100,
          toAddress: toAddress,
        }],
        excludeUnconfirmedUtxos: true,
        feePerKb: 1,
      };
      clients[0].createTxProposal(opts, function(err, txp) {
        should.not.exist(err);
        should.exist(txp);
        var t = new WalletClient.API().buildTx(txp);
        should.not.exist(t.getChangeOutput());
        clients[0].publishTxProposal({
          txp: txp,
        }, function(err, publishedTxp) {
          should.not.exist(err);
          should.exist(publishedTxp);
          publishedTxp.status.should.equal('pending');
          clients[0].signTxProposal(publishedTxp, function(err, txp) {
            should.not.exist(err);
            clients[1].signTxProposal(publishedTxp, function(err, txp) {
              should.not.exist(err);
              txp.status.should.equal('accepted');
              done();
            });
          });
        });
      });
    });

    it('Should sign proposal created with send max settings', function(done) {
      var toAddress = 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5';
      clients[0].getSendMaxInfo({
        feePerKb: 100e2,
        returnInputs: true
      }, function(err, info) {
        should.not.exist(err);
        var opts = {
          outputs: [{
            amount: info.amount,
            toAddress: toAddress,
          }],
          inputs: info.inputs,
          fee: info.fee,
        };
        clients[0].createTxProposal(opts, function(err, txp) {
          should.not.exist(err);
          should.exist(txp);
          var t = new WalletClient.API().buildTx(txp);
          should.not.exist(t.getChangeOutput());
          clients[0].publishTxProposal({
            txp: txp,
          }, function(err, publishedTxp) {
            should.not.exist(err);
            should.exist(publishedTxp);
            publishedTxp.status.should.equal('pending');
            clients[0].signTxProposal(publishedTxp, function(err, txp) {
              should.not.exist(err);
              clients[1].signTxProposal(publishedTxp, function(err, txp) {
                should.not.exist(err);
                txp.status.should.equal('accepted');
                clients[0].getBalance({}, function(err, balance) {
                  should.not.exist(err);
                  balance.lockedAmount.should.equal(5e8);
                  done();
                });
              });
            });
          });
        });
      });
    });
  });

  describe('Payment Protocol', function() {
    var http;

    describe('Shared wallet', function() {
      beforeEach(function(done) {
        http = sinon.stub();
        http.yields(null, TestData.payProBuf);
        helpers.createAndJoinWallet(clients, 2, 2, function(w) {
          clients[0].createAddress({}, function(err, x0) {
            should.not.exist(err);
            should.exist(x0.address);
            blockchainExplorerMock.setUtxo(x0, 1, 2);
            blockchainExplorerMock.setUtxo(x0, 1, 2);
            var opts = {
              payProUrl: 'dummy',
            };
            clients[0].payProHttp = clients[1].payProHttp = http;

            clients[0].fetchPayPro(opts, function(err, paypro) {
              helpers.createAndPublishTxProposal(clients[0], {
                toAddress: paypro.toAddress,
                amount: paypro.amount,
                message: paypro.memo,
                payProUrl: opts.payProUrl,
              }, function(err, x) {
                should.not.exist(err);
                done();
              });
            });
          });
        });
      });

      it('Should Create and Verify a Tx from PayPro', function(done) {
        clients[1].getTxProposals({}, function(err, txps) {
          should.not.exist(err);
          var tx = txps[0];
          // From the hardcoded paypro request
          tx.outputs[0].amount.should.equal(404500);
          tx.outputs[0].toAddress.should.equal('mjfjcbuYwBUdEyq2m7AezjCAR4etUBqyiE');
          tx.message.should.equal('Payment request for BitPay invoice CibEJJtG1t9H77KmM61E2t for merchant testCopay');
          tx.payProUrl.should.equal('dummy');
          done();
        });
      });

      it('Should handle broken paypro data', function(done) {
        http = sinon.stub();
        http.yields(null, 'a broken data');
        clients[0].payProHttp = http;
        var opts = {
          payProUrl: 'dummy',
        };
        clients[0].fetchPayPro(opts, function(err, paypro) {
          should.exist(err);
          err.message.should.contain('parse');
          done();
        });
      });

      it('Should ignore PayPro at getTxProposals if instructed', function(done) {
        http.yields(null, 'kaka');
        clients[1].doNotVerifyPayPro = true;
        clients[1].getTxProposals({}, function(err, txps) {
          should.not.exist(err);
          var tx = txps[0];
          // From the hardcoded paypro request
          tx.outputs[0].amount.should.equal(404500);
          tx.outputs[0].toAddress.should.equal('mjfjcbuYwBUdEyq2m7AezjCAR4etUBqyiE');
          tx.message.should.equal('Payment request for BitPay invoice CibEJJtG1t9H77KmM61E2t for merchant testCopay');
          tx.payProUrl.should.equal('dummy');
          done();
        });
      });

      it('Should ignore PayPro at signTxProposal if instructed', function(done) {
        http.yields(null, 'kaka');
        clients[1].doNotVerifyPayPro = true;
        clients[1].getTxProposals({}, function(err, txps) {
          should.not.exist(err);
          clients[1].signTxProposal(txps[0], function(err, txps) {
            should.not.exist(err);
            done();
          });
        });
      });

      it('Should send the "payment message" when last copayer sign', function(done) {
        clients[0].getTxProposals({}, function(err, txps) {
          should.not.exist(err);
          clients[0].signTxProposal(txps[0], function(err, xx, paypro) {
            should.not.exist(err);
            clients[1].signTxProposal(xx, function(err, yy, paypro) {
              should.not.exist(err);
              yy.status.should.equal('accepted');
              http.onCall(5).yields(null, TestData.payProAckBuf);

              clients[1].broadcastTxProposal(yy, function(err, zz, memo) {
                should.not.exist(err);
                var args = http.lastCall.args[0];
                args.method.should.equal('POST');
                args.body.length.should.be.within(440, 460);
                memo.should.equal('Transaction received by BitPay. Invoice will be marked as paid if the transaction is confirmed.');
                zz.message.should.equal('Payment request for BitPay invoice CibEJJtG1t9H77KmM61E2t for merchant testCopay');
                done();
              });
            });
          });
        });
      });

      it('Should send correct refund address', function(done) {
        clients[0].getTxProposals({}, function(err, txps) {
          should.not.exist(err);
          var changeAddress = txps[0].changeAddress.address;
          clients[0].signTxProposal(txps[0], function(err, xx, paypro) {
            should.not.exist(err);
            clients[1].signTxProposal(xx, function(err, yy, paypro) {
              should.not.exist(err);
              yy.status.should.equal('accepted');
              http.onCall(5).yields(null, TestData.payProAckBuf);

              clients[1].broadcastTxProposal(yy, function(err, zz, memo) {
                should.not.exist(err);
                var args = http.lastCall.args[0];
                var data = payProLib.Payment.decode(args.body);
                var pay = new PayPro();
                var p = pay.makePayment(data);
                var refund_to = p.get('refund_to');
                refund_to.length.should.equal(1);

                refund_to = refund_to[0];

                var amount = refund_to.get('amount')
                amount.low.should.equal(404500);
                amount.high.should.equal(0);
                var s = refund_to.get('script');
                s = new Script(s.buffer.slice(s.offset, s.limit));
                var addr = new Address.fromScript(s, 'testnet');
                addr.toString().should.equal(changeAddress);
                done();
              });
            });
          });
        });
      });

      it('Should send the signed tx in paypro', function(done) {
        clients[0].getTxProposals({}, function(err, txps) {
          should.not.exist(err);
          var changeAddress = txps[0].changeAddress.address;
          clients[0].signTxProposal(txps[0], function(err, xx, paypro) {
            should.not.exist(err);
            clients[1].signTxProposal(xx, function(err, yy, paypro) {
              should.not.exist(err);
              yy.status.should.equal('accepted');
              http.onCall(5).yields(null, TestData.payProAckBuf);

              clients[1].broadcastTxProposal(yy, function(err, zz, memo) {

                should.not.exist(err);
                var args = http.lastCall.args[0];
                var data = PayPro.Payment.decode(args.body);
                var pay = new PayPro();
                var p = pay.makePayment(data);
                var rawTx = p.get('transactions')[0].toBuffer();
                var tx = new Transaction(rawTx);
                var script = tx.inputs[0].script;
                script.isScriptHashIn().should.equal(true);
                done();
              });
            });
          });
        });
      });
    });

    describe('1-of-1 wallet', function() {
      beforeEach(function(done) {
        http = sinon.stub();
        http.yields(null, TestData.payProBuf);
        helpers.createAndJoinWallet(clients, 1, 1, function(w) {
          clients[0].createAddress({}, function(err, x0) {
            should.not.exist(err);
            should.exist(x0.address);
            blockchainExplorerMock.setUtxo(x0, 1, 2);
            blockchainExplorerMock.setUtxo(x0, 1, 2);
            var opts = {
              payProUrl: 'dummy',
            };
            clients[0].payProHttp = clients[1].payProHttp = http;

            clients[0].fetchPayPro(opts, function(err, paypro) {
              helpers.createAndPublishTxProposal(clients[0], {
                toAddress: paypro.toAddress,
                amount: paypro.amount,
                message: paypro.memo,
                payProUrl: opts.payProUrl,
              }, function(err, x) {
                should.not.exist(err);
                done();
              });
            });
          });
        });
      });

      it('Should send correct refund address', function(done) {
        clients[0].getTxProposals({}, function(err, txps) {
          should.not.exist(err);
          var changeAddress = txps[0].changeAddress.address;
          clients[0].signTxProposal(txps[0], function(err, xx, paypro) {
            should.not.exist(err);
            xx.status.should.equal('accepted');
            http.onCall(5).yields(null, TestData.payProAckBuf);

            clients[0].broadcastTxProposal(xx, function(err, zz, memo) {
              should.not.exist(err);
              var args = http.lastCall.args[0];
              var data = PayPro.Payment.decode(args.body);
              var pay = new PayPro();
              var p = pay.makePayment(data);
              var refund_to = p.get('refund_to');
              refund_to.length.should.equal(1);

              refund_to = refund_to[0];

              var amount = refund_to.get('amount')
              amount.low.should.equal(404500);
              amount.high.should.equal(0);
              var s = refund_to.get('script');
              s = new Script(s.buffer.slice(s.offset, s.limit));
              var addr = new Address.fromScript(s, 'testnet');
              addr.toString().should.equal(changeAddress);
              done();
            });
          });
        });
      });

      it('Should send the signed tx in paypro', function(done) {
        clients[0].getTxProposals({}, function(err, txps) {
          should.not.exist(err);
          var changeAddress = txps[0].changeAddress.address;
          clients[0].signTxProposal(txps[0], function(err, xx, paypro) {
            should.not.exist(err);
            xx.status.should.equal('accepted');
            http.onCall(5).yields(null, TestData.payProAckBuf);

            clients[0].broadcastTxProposal(xx, function(err, zz, memo) {
              should.not.exist(err);
              var args = http.lastCall.args[0];
              var data = PayPro.Payment.decode(args.body);
              var pay = new PayPro();
              var p = pay.makePayment(data);
              var rawTx = p.get('transactions')[0].toBuffer();
              var tx = new Transaction(rawTx);
              var script = tx.inputs[0].script;
              script.isPublicKeyHashIn().should.equal(true);
              done();
            });
          });
        });
      });
    });

    describe('New proposal flow', function() {
      beforeEach(function(done) {
        http = sinon.stub();
        http.yields(null, TestData.payProBuf);
        helpers.createAndJoinWallet(clients, 2, 2, function(w) {
          clients[0].createAddress({}, function(err, x0) {
            should.not.exist(err);
            should.exist(x0.address);
            blockchainExplorerMock.setUtxo(x0, 1, 2);
            blockchainExplorerMock.setUtxo(x0, 1, 2);
            var opts = {
              payProUrl: 'dummy',
            };
            clients[0].payProHttp = clients[1].payProHttp = http;

            clients[0].fetchPayPro(opts, function(err, paypro) {
              clients[0].createTxProposal({
                outputs: [{
                  toAddress: paypro.toAddress,
                  amount: paypro.amount,
                }],
                message: paypro.memo,
                payProUrl: opts.payProUrl,
                feePerKb: 100e2,
              }, function(err, txp) {
                should.not.exist(err);
                clients[0].publishTxProposal({
                  txp: txp
                }, function(err) {
                  should.not.exist(err);
                  done();
                });
              });
            });
          });
        });
      });

      it('Should Create and Verify a Tx from PayPro', function(done) {
        clients[1].getTxProposals({}, function(err, txps) {
          should.not.exist(err);
          var tx = txps[0];
          // From the hardcoded paypro request
          tx.amount.should.equal(404500);
          tx.outputs[0].toAddress.should.equal('mjfjcbuYwBUdEyq2m7AezjCAR4etUBqyiE');
          tx.message.should.equal('Payment request for BitPay invoice CibEJJtG1t9H77KmM61E2t for merchant testCopay');
          tx.payProUrl.should.equal('dummy');
          done();
        });
      });
    });
  });

  describe('Proposals with explicit ID', function() {
    it('Should create and publish a proposal', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function(w) {
        var id = 'anId';
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          blockchainExplorerMock.setUtxo(x0, 1, 2);
          var toAddress = 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5';
          var opts = {
            outputs: [{
              amount: 40000,
              toAddress: toAddress,
            }],
            feePerKb: 100e2,
            txProposalId: id,
          };
          clients[0].createTxProposal(opts, function(err, txp) {
            should.not.exist(err);
            should.exist(txp);
            clients[0].publishTxProposal({
              txp: txp,
            }, function(err, publishedTxp) {
              should.not.exist(err);
              publishedTxp.id.should.equal(id);
              clients[0].removeTxProposal(publishedTxp, function(err) {
                opts.txProposalId = null;
                clients[0].createTxProposal(opts, function(err, txp) {
                  should.not.exist(err);
                  should.exist(txp);
                  txp.id.should.not.equal(id);
                  done();
                });
              });
            });
          });
        });
      });
    });
  });

  describe('Multiple output proposals', function() {
    var toAddress = 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5';
    var opts = {
      message: 'hello',
      outputs: [{
        amount: 10000,
        toAddress: toAddress,
        message: 'world',
      }],
      feePerKb: 100e2,
    };

    beforeEach(function(done) {
      var http = sinon.stub();
      http.yields(null, TestData.payProBuf);
      helpers.createAndJoinWallet(clients, 1, 1, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          blockchainExplorerMock.setUtxo(x0, 1, 1);
          clients[0].payProHttp = clients[1].payProHttp = http;
          done();
        });
      });
    });

    function doit(opts, doNotVerifyPayPro, doBroadcast, done) {
      helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
        should.not.exist(err);
        clients[0].getTx(x.id, function(err, x2) {
          should.not.exist(err);
          x2.creatorName.should.equal('creator');
          x2.message.should.equal('hello');
          x2.outputs[0].toAddress.should.equal(toAddress);
          x2.outputs[0].amount.should.equal(10000);
          x2.outputs[0].message.should.equal('world');
          clients[0].doNotVerifyPayPro = doNotVerifyPayPro;
          clients[0].signTxProposal(x2, function(err, txp) {
            should.not.exist(err);
            txp.status.should.equal('accepted');
            if (doBroadcast) {
              clients[0].broadcastTxProposal(txp, function(err, txp) {
                should.not.exist(err);
                txp.status.should.equal('broadcasted');
                txp.txid.should.equal((new Transaction(blockchainExplorerMock.lastBroadcasted)).id);
                done();
              });
            } else {
              done();
            }
          });
        });
      });
    };

    it('should create, get, sign, and broadcast proposal with no payProUrl', function(done) {
      delete opts.payProUrl;
      doit(opts, false, true, done);
    });

    it('should create, get, sign, and broadcast proposal with null payProUrl', function(done) {
      opts.payProUrl = null;
      doit(opts, false, true, done);
    });

    it('should create, get, sign, and broadcast proposal with empty string payProUrl', function(done) {
      opts.payProUrl = '';
      doit(opts, false, true, done);
    });

    it('should create, get, and sign proposal with mal-formed payProUrl', function(done) {
      opts.payProUrl = 'dummy';
      doit(opts, true, false, done);
    });

    it('should create, get, and sign proposal with well-formed payProUrl', function(done) {
      opts.payProUrl = 'https://merchant.com/pay.php?h%3D2a8628fc2fbe';
      doit(opts, true, false, done);
    });
  });

  describe('Transactions Signatures and Rejection', function() {
    this.timeout(5000);
    it('Send and broadcast in 1-1 wallet', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          blockchainExplorerMock.setUtxo(x0, 1, 1);
          var opts = {
            outputs: [{
              amount: 10000000,
              toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
              message: 'output 0',
            }],
            message: 'hello',
            feePerKb: 100e2,
          };
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, txp) {
            should.not.exist(err);
            txp.requiredRejections.should.equal(1);
            txp.requiredSignatures.should.equal(1);
            txp.status.should.equal('pending');
            txp.changeAddress.path.should.equal('m/1/0');
            txp.outputs[0].message.should.equal('output 0');
            txp.message.should.equal('hello');
            clients[0].signTxProposal(txp, function(err, txp) {
              should.not.exist(err);
              txp.status.should.equal('accepted');
              txp.outputs[0].message.should.equal('output 0');
              txp.message.should.equal('hello');
              clients[0].broadcastTxProposal(txp, function(err, txp) {
                should.not.exist(err);
                txp.status.should.equal('broadcasted');
                txp.txid.should.equal((new Transaction(blockchainExplorerMock.lastBroadcasted)).id);
                txp.outputs[0].message.should.equal('output 0');
                txp.message.should.equal('hello');
                done();
              });
            });
          });
        });
      });
    });

    it('should sign if signatures are empty', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          blockchainExplorerMock.setUtxo(x0, 1, 1);
          var opts = {
            amount: 10000000,
            toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
            message: 'hello',
          };
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, txp) {
            should.not.exist(err);
            txp.requiredRejections.should.equal(1);
            txp.requiredSignatures.should.equal(1);
            txp.status.should.equal('pending');
            txp.changeAddress.path.should.equal('m/1/0');

            txp.signatures = [];
            clients[0].signTxProposal(txp, function(err, txp) {
              should.not.exist(err);
              txp.status.should.equal('accepted');
              done();
            });
          });
        });
      });
    });

    it('Send and broadcast in 2-3 wallet', function(done) {
      helpers.createAndJoinWallet(clients, 2, 3, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          blockchainExplorerMock.setUtxo(x0, 10, 2);
          var opts = {
            amount: 10000,
            toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
            message: 'hello',
          };
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, txp) {
            should.not.exist(err);
            clients[0].getStatus({}, function(err, st) {
              should.not.exist(err);
              var txp = st.pendingTxps[0];
              txp.status.should.equal('pending');
              txp.requiredRejections.should.equal(2);
              txp.requiredSignatures.should.equal(2);
              var w = st.wallet;
              w.copayers.length.should.equal(3);
              w.status.should.equal('complete');
              var b = st.balance;
              b.totalAmount.should.equal(1000000000);
              b.lockedAmount.should.equal(1000000000);
              clients[0].signTxProposal(txp, function(err, txp) {
                should.not.exist(err, err);
                txp.status.should.equal('pending');
                clients[1].signTxProposal(txp, function(err, txp) {
                  should.not.exist(err);
                  txp.status.should.equal('accepted');
                  clients[1].broadcastTxProposal(txp, function(err, txp) {
                    txp.status.should.equal('broadcasted');
                    txp.txid.should.equal((new Transaction(blockchainExplorerMock.lastBroadcasted)).id);
                    done();
                  });
                });
              });
            });
          });
        });
      });
    });

    it('Send, reject actions in 2-3 wallet must have correct copayerNames', function(done) {
      helpers.createAndJoinWallet(clients, 2, 3, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          blockchainExplorerMock.setUtxo(x0, 10, 2);
          var opts = {
            amount: 10000,
            toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
            message: 'hello 1-1',
          };
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, txp) {
            should.not.exist(err);
            clients[0].rejectTxProposal(txp, 'wont sign', function(err, txp) {
              should.not.exist(err, err);
              clients[1].signTxProposal(txp, function(err, txp) {
                should.not.exist(err);
                done();
              });
            });
          });
        });
      });
    });

    it('Send, reject, 2 signs and broadcast in 2-3 wallet', function(done) {
      helpers.createAndJoinWallet(clients, 2, 3, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          blockchainExplorerMock.setUtxo(x0, 10, 2);
          var opts = {
            amount: 10000,
            toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
            message: 'hello 1-1',
          };
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, txp) {
            should.not.exist(err);
            txp.status.should.equal('pending');
            txp.requiredRejections.should.equal(2);
            txp.requiredSignatures.should.equal(2);
            clients[0].rejectTxProposal(txp, 'wont sign', function(err, txp) {
              should.not.exist(err, err);
              txp.status.should.equal('pending');
              clients[1].signTxProposal(txp, function(err, txp) {
                should.not.exist(err);
                clients[2].signTxProposal(txp, function(err, txp) {
                  should.not.exist(err);
                  txp.status.should.equal('accepted');
                  clients[2].broadcastTxProposal(txp, function(err, txp) {
                    txp.status.should.equal('broadcasted');
                    txp.txid.should.equal((new Transaction(blockchainExplorerMock.lastBroadcasted)).id);
                    done();
                  });
                });
              });
            });
          });
        });
      });
    });

    it('Send, reject in 3-4 wallet', function(done) {
      helpers.createAndJoinWallet(clients, 3, 4, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          blockchainExplorerMock.setUtxo(x0, 10, 3);
          var opts = {
            amount: 10000,
            toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
            message: 'hello 1-1',
          };
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, txp) {
            should.not.exist(err);
            txp.status.should.equal('pending');
            txp.requiredRejections.should.equal(2);
            txp.requiredSignatures.should.equal(3);

            clients[0].rejectTxProposal(txp, 'wont sign', function(err, txp) {
              should.not.exist(err, err);
              txp.status.should.equal('pending');
              clients[1].signTxProposal(txp, function(err, txp) {
                should.not.exist(err);
                txp.status.should.equal('pending');
                clients[2].rejectTxProposal(txp, 'me neither', function(err, txp) {
                  should.not.exist(err);
                  txp.status.should.equal('rejected');
                  done();
                });
              });
            });
          });
        });
      });
    });

    it('Should not allow to reject or sign twice', function(done) {
      helpers.createAndJoinWallet(clients, 2, 3, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          blockchainExplorerMock.setUtxo(x0, 10, 2);
          var opts = {
            amount: 10000,
            toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
            message: 'hello 1-1',
          };
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, txp) {
            should.not.exist(err);
            txp.status.should.equal('pending');
            txp.requiredRejections.should.equal(2);
            txp.requiredSignatures.should.equal(2);
            clients[0].signTxProposal(txp, function(err, txp) {
              should.not.exist(err);
              txp.status.should.equal('pending');
              clients[0].signTxProposal(txp, function(err) {
                should.exist(err);
                err.should.be.an.instanceOf(Errors.COPAYER_VOTED);
                clients[1].rejectTxProposal(txp, 'xx', function(err, txp) {
                  should.not.exist(err);
                  clients[1].rejectTxProposal(txp, 'xx', function(err) {
                    should.exist(err);
                    err.should.be.an.instanceOf(Errors.COPAYER_VOTED);
                    done();
                  });
                });
              });
            });
          });
        });
      });
    });
  });

  describe('Broadcast raw transaction', function() {
    it('should broadcast raw tx', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function(w) {
        var opts = {
          networkName: 'testnet',
          rawTx: '0100000001b1b1b1b0d9786e237ec6a4b80049df9e926563fee7bdbc1ac3c4efc3d0af9a1c010000006a47304402207c612d36d0132ed463526a4b2370de60b0aa08e76b6f370067e7915c2c74179b02206ae8e3c6c84cee0bca8521704eddb40afe4590f14fd5d6434da980787ba3d5110121031be732b984b0f1f404840f2479bcc81f90187298efecc67dd83e1f93d9b2860dfeffffff0200ab9041000000001976a91403383bd4cff200de3690db1ed17d0b1a228ea43f88ac25ad6ed6190000001976a9147ccbaf7bcc1e323548bd1d57d7db03f6e6daf76a88acaec70700',
        };
        clients[0].broadcastRawTx(opts, function(err, txid) {
          should.not.exist(err);
          txid.should.equal('d19871cf7c123d413ac71f9240ea234fac77bc95bcf41015d8bf5c03f221b92c');
          done();
        });
      });
    });
  });

  describe('Transaction history', function() {
    it('should get transaction history', function(done) {
      blockchainExplorerMock.setHistory(TestData.history);
      helpers.createAndJoinWallet(clients, 1, 1, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          clients[0].getTxHistory({}, function(err, txs) {
            should.not.exist(err);
            should.exist(txs);
            txs.length.should.equal(2);
            done();
          });
        });
      });
    });

    it('should get empty transaction history when there are no addresses', function(done) {
      blockchainExplorerMock.setHistory(TestData.history);
      helpers.createAndJoinWallet(clients, 1, 1, function(w) {
        clients[0].getTxHistory({}, function(err, txs) {
          should.not.exist(err);
          should.exist(txs);
          txs.length.should.equal(0);
          done();
        });
      });
    });

    it('should get transaction history decorated with proposal & notes', function(done) {
      this.timeout(5000);
      async.waterfall([

        function(next) {
          helpers.createAndJoinWallet(clients, 2, 3, function(w) {
            clients[0].createAddress({}, function(err, address) {
              should.not.exist(err);
              should.exist(address);
              next(null, address);
            });
          });
        },
        function(address, next) {
          blockchainExplorerMock.setUtxo(address, 10, 2);
          var opts = {
            amount: 10000,
            toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
            message: 'some message',
          };
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, txp) {
            should.not.exist(err);
            clients[1].rejectTxProposal(txp, 'some reason', function(err, txp) {
              should.not.exist(err);
              clients[2].signTxProposal(txp, function(err, txp) {
                should.not.exist(err);
                clients[0].signTxProposal(txp, function(err, txp) {
                  should.not.exist(err);
                  txp.status.should.equal('accepted');
                  clients[0].broadcastTxProposal(txp, function(err, txp) {
                    should.not.exist(err);
                    txp.status.should.equal('broadcasted');
                    next(null, txp);
                  });
                });
              });
            });
          });
        },
        function(txp, next) {
          clients[1].editTxNote({
            txid: txp.txid,
            body: 'just a note'
          }, function(err) {
            return next(err, txp);
          });
        },
        function(txp, next) {
          var history = lodash.cloneDeep(TestData.history);
          history[0].txid = txp.txid;
          lodash.each(history, function(h) {
            h.blocktime = Math.floor(Date.now() / 1000);
          });
          blockchainExplorerMock.setHistory(history);
          clients[0].getTxHistory({}, function(err, txs) {
            should.not.exist(err);
            should.exist(txs);
            txs.length.should.equal(2);
            var decorated = lodash.find(txs, {
              txid: txp.txid
            });
            should.exist(decorated);
            decorated.proposalId.should.equal(txp.id);
            decorated.message.should.equal('some message');
            decorated.actions.length.should.equal(3);
            var rejection = lodash.find(decorated.actions, {
              type: 'reject'
            });
            should.exist(rejection);
            rejection.comment.should.equal('some reason');

            var note = decorated.note;
            should.exist(note);
            note.body.should.equal('just a note');
            note.editedByName.should.equal('copayer 1');
            next();
          });
        }
      ], function(err) {
        should.not.exist(err);
        done();
      });
    });

    it('should get paginated transaction history', function(done) {
      var testCases = [{
        opts: {},
        expected: [20, 10]
      }, {
        opts: {
          skip: 1,
        },
        expected: [10]
      }, {
        opts: {
          limit: 1,
        },
        expected: [20]
      }, {
        opts: {
          skip: 3,
        },
        expected: []
      }, {
        opts: {
          skip: 1,
          limit: 10,
        },
        expected: [10]
      }, ];

      blockchainExplorerMock.setHistory(TestData.history);
      helpers.createAndJoinWallet(clients, 1, 1, function(w) {
        clients[0].createAddress({}, function(err, x0) {
          should.not.exist(err);
          should.exist(x0.address);
          async.each(testCases, function(testCase, next) {
            clients[0].getTxHistory(testCase.opts, function(err, txs) {
              should.not.exist(err);
              should.exist(txs);
              var times = lodash.map(txs, 'time');
              times.should.deep.equal(testCase.expected);
              next();
            });
          }, done);
        });
      });
    });
  });

  describe('Transaction notes', function(done) {
    beforeEach(function(done) {
      helpers.createAndJoinWallet(clients, 1, 2, function(w) {
        done();
      });
    });

    it('should edit a note for an arbitrary txid', function(done) {
      clients[0].editTxNote({
        txid: '123',
        body: 'note body'
      }, function(err, note) {
        should.not.exist(err);
        should.exist(note);
        note.body.should.equal('note body');
        clients[0].getTxNote({
          txid: '123',
        }, function(err, note) {
          should.not.exist(err);
          should.exist(note);
          note.txid.should.equal('123');
          note.walletId.should.equal(clients[0].credentials.walletId);
          note.body.should.equal('note body');
          note.editedBy.should.equal(clients[0].credentials.copayerId);
          note.editedByName.should.equal(clients[0].credentials.copayerName);
          note.createdOn.should.equal(note.editedOn);
          done();
        });
      });
    });

    it('should not send note body in clear text', function(done) {
      var spy = sinon.spy(clients[0], '_doPutRequest');
      clients[0].editTxNote({
        txid: '123',
        body: 'a random note'
      }, function(err) {
        should.not.exist(err);
        var url = spy.getCall(0).args[0];
        var body = JSON.stringify(spy.getCall(0).args[1]);
        url.should.contain('/txnotes');
        body.should.contain('123');
        body.should.not.contain('a random note');
        done();
      });
    });

    it('should share notes between copayers', function(done) {
      clients[0].editTxNote({
        txid: '123',
        body: 'note body'
      }, function(err) {
        should.not.exist(err);
        clients[0].getTxNote({
          txid: '123',
        }, function(err, note) {
          should.not.exist(err);
          should.exist(note);
          note.editedBy.should.equal(clients[0].credentials.copayerId);
          var creator = note.editedBy;
          clients[1].getTxNote({
            txid: '123',
          }, function(err, note) {
            should.not.exist(err);
            should.exist(note);
            note.body.should.equal('note body');
            note.editedBy.should.equal(creator);
            done();
          });
        });
      });
    });

    it('should get all notes edited past a given date', function(done) {
      var clock = sinon.useFakeTimers('Date');
      async.series([

        function(next) {
          clients[0].getTxNotes({}, function(err, notes) {
            should.not.exist(err);
            notes.should.be.empty;
            next();
          });
        },
        function(next) {
          clients[0].editTxNote({
            txid: '123',
            body: 'note body'
          }, next);
        },
        function(next) {
          clients[0].getTxNotes({
            minTs: 0,
          }, function(err, notes) {
            should.not.exist(err);
            notes.length.should.equal(1);
            notes[0].txid.should.equal('123');
            next();
          });
        },
        function(next) {
          clock.tick(60 * 1000);
          clients[0].editTxNote({
            txid: '456',
            body: 'another note'
          }, next);
        },
        function(next) {
          clients[0].getTxNotes({
            minTs: 0,
          }, function(err, notes) {
            should.not.exist(err);
            notes.length.should.equal(2);
            lodash.difference(lodash.map(notes, 'txid'), ['123', '456']).should.be.empty;
            next();
          });
        },
        function(next) {
          clients[0].getTxNotes({
            minTs: 50,
          }, function(err, notes) {
            should.not.exist(err);
            notes.length.should.equal(1);
            notes[0].txid.should.equal('456');
            next();
          });
        },
        function(next) {
          clock.tick(60 * 1000);
          clients[0].editTxNote({
            txid: '123',
            body: 'an edit'
          }, next);
        },
        function(next) {
          clients[0].getTxNotes({
            minTs: 100,
          }, function(err, notes) {
            should.not.exist(err);
            notes.length.should.equal(1);
            notes[0].txid.should.equal('123');
            notes[0].body.should.equal('an edit');
            next();
          });
        },
        function(next) {
          clients[0].getTxNotes({}, function(err, notes) {
            should.not.exist(err);
            notes.length.should.equal(2);
            next();
          });
        },
      ], function(err) {
        should.not.exist(err);
        clock.restore();
        done();
      });
    });
  });

  describe('Mobility, backup & restore', function() {
    describe('Export & Import', function() {
      var address, importedClient;
      describe('Compliant derivation', function() {
        beforeEach(function(done) {
          importedClient = null;
          helpers.createAndJoinWallet(clients, 1, 1, function() {
            clients[0].createAddress({}, function(err, addr) {
              should.not.exist(err);
              should.exist(addr.address);
              address = addr.address;
              done();
            });
          });
        });

        afterEach(function(done) {
          if (!importedClient) return done();
          importedClient.getMainAddresses({}, function(err, list) {
            should.not.exist(err);
            should.exist(list);
            list.length.should.equal(1);
            list[0].address.should.equal(address);
            done();
          });
        });

        it('should export & import', function() {
          var exported = clients[0].export();

          importedClient = helpers.newClient(app);
          importedClient.import(exported);
        });

        it('should export without signing rights', function() {
          clients[0].canSign().should.be.true;
          var exported = clients[0].export({
            noSign: true,
          });

          importedClient = helpers.newClient(app);
          importedClient.import(exported);
          importedClient.canSign().should.be.false;
        });

        it('should export & import encrypted', function() {
          clients[0].encryptPrivateKey('password');

          var exported = clients[0].export();

          importedClient = helpers.newClient(app);
          importedClient.import(exported);

          importedClient.isPrivKeyEncrypted().should.be.true;
        });

        it('should export & import decrypted when password is supplied', function() {
          clients[0].encryptPrivateKey('password');

          var exported = clients[0].export({
            password: 'password'
          });

          importedClient = helpers.newClient(app);
          importedClient.import(exported);

          importedClient.isPrivKeyEncrypted().should.be.false;
          clients[0].isPrivKeyEncrypted().should.be.true;
          should.not.exist(clients[0].xPrivKey);
          should.not.exist(clients[0].mnemonic);
        });

        it('should fail if wrong password provided', function() {
          clients[0].encryptPrivateKey('password');

          var exported = clients[0].export({
            password: 'password'
          });

          var err;
          try {
            var exported = clients[0].export({
              password: 'wrong'
            });
          } catch (ex) {
            err = ex;
          }
          should.exist(err);
        });

        it('should export & import with mnemonics + wallet service', function(done) {
          var c = clients[0].credentials;
          var walletId = c.walletId;
          var walletName = c.walletName;
          var copayerName = c.copayerName;
          var key = c.xPrivKey;

          var exported = clients[0].getMnemonic();
          importedClient = helpers.newClient(app);
          importedClient.importFromMnemonic(exported, {
            networkName: c.networkName,
          }, function(err) {
            var c2 = importedClient.credentials;
            c2.xPrivKey.should.equal(key);
            should.not.exist(err);
            c2.walletId.should.equal(walletId);
            c2.walletName.should.equal(walletName);
            c2.copayerName.should.equal(copayerName);
            done();
          });
        });

        it('should export & import with xprivkey + wallet service', function(done) {
          var c = clients[0].credentials;
          var walletId = c.walletId;
          var walletName = c.walletName;
          var copayerName = c.copayerName;
          var network = c.networkName;
          var key = c.xPrivKey;

          var exported = clients[0].getMnemonic();
          importedClient = helpers.newClient(app);
          importedClient.importFromExtendedPrivateKey(key, {}, function(err) {
            var c2 = importedClient.credentials;
            c2.xPrivKey.should.equal(key);
            should.not.exist(err);
            c2.walletId.should.equal(walletId);
            c2.walletName.should.equal(walletName);
            c2.copayerName.should.equal(copayerName);
            done();
          });
        });
      });

      describe('Non-compliant derivation', function() {
        function setup(done) {
          clients[0].createWallet('mywallet', 'creator', 1, 1, {
            networkName: 'btc'
          }, function(err) {
            should.not.exist(err);
            clients[0].createAddress({}, function(err, addr) {
              should.not.exist(err);
              address = addr.address;
              done();
            });
          });
        };

        beforeEach(function() {
          importedClient = null;
        });

        afterEach(function(done) {
          if (!importedClient) return done();
          importedClient.getMainAddresses({}, function(err, list) {
            should.not.exist(err);
            should.exist(list);
            list.length.should.equal(1);
            list[0].address.should.equal(address);
            done();
          });
        });

        it('should check wallet service once if specific derivation is not problematic', function(done) {
          clients[0].seedFromMnemonic('relax about label gentle insect cross summer helmet come price elephant seek', {
            networkName: 'btc',
          });
          importedClient = helpers.newClient(app);
          var spy = sinon.spy(importedClient, 'openWallet');
          importedClient.importFromMnemonic(clients[0].getMnemonic(), {
            networkName: 'btc',
          }, function(err) {
            should.exist(err);
            err.should.be.an.instanceOf(Errors.UNAUTHORIZED);
            spy.getCalls().length.should.equal(1);
            importedClient = null;
            done();
          });
        });

        it('should export & import with xprivkey + wallet service', function(done) {
          clients[0].seedFromMnemonic('relax about label gentle insect cross summer helmet come price elephant seek', {
            networkName: 'btc',
          });
          importedClient = helpers.newClient(app);
          var spy = sinon.spy(importedClient, 'openWallet');
          importedClient.importFromExtendedPrivateKey(clients[0].getKeys().xPrivKey, {
            networkName: 'btc',
          }, function(err) {
            should.exist(err);
            err.should.be.an.instanceOf(Errors.UNAUTHORIZED);
            spy.getCalls().length.should.equal(1);
            importedClient = null;
            done();
          });
        });
      });
    });

    describe('#validateKeyDerivation', function() {
      beforeEach(function(done) {
        helpers.createAndJoinWallet(clients, 1, 1, function() {
          done();
        });
      });

      it('should validate key derivation', function(done) {
        clients[0].validateKeyDerivation({}, function(err, isValid) {
          should.not.exist(err);
          isValid.should.be.true;
          clients[0].keyDerivationOk.should.be.true;

          var exported = JSON.parse(clients[0].export());

          // Tamper export with a wrong xpub
          exported.xPubKey = 'tpubD6NzVbkrYhZ4XJEQQWBgysPKJcBv8zLhHpfhcw4RyhakMxmffNRRRFDUe1Zh7fxvjt1FdNJcaxHgqxyKLL8XiZug7C8KJFLFtGfPVBcY6Nb';

          var importedClient = helpers.newClient(app);
          should.not.exist(importedClient.keyDerivationOk);

          importedClient.import(JSON.stringify(exported));
          importedClient.validateKeyDerivation({}, function(err, isValid) {
            should.not.exist(err);
            isValid.should.be.false;
            importedClient.keyDerivationOk.should.be.false;
            done();
          });
        });
      });
    });

    describe('Mnemonic related tests', function() {
      var importedClient;

      it('should import with mnemonics livenet', function(done) {
        var client = helpers.newClient(app);
        client.seedFromRandomWithMnemonic();
        var exported = client.getMnemonic();
        client.createWallet('mywallet', 'creator', 1, 1, {
          networkName: 'btc'
        }, function(err) {
          should.not.exist(err);
          var c = client.credentials;
          importedClient = helpers.newClient(app);
          importedClient.importFromMnemonic(exported, {}, function(err) {
            should.not.exist(err);
            var c2 = importedClient.credentials;
            c2.networkName.should.equal('btc');
            c2.xPubKey.should.equal(client.credentials.xPubKey);
            c2.personalEncryptingKey.should.equal(c.personalEncryptingKey);
            c2.walletId.should.equal(c.walletId);
            c2.walletName.should.equal(c.walletName);
            c2.copayerName.should.equal(c.copayerName);
            done();
          });
        });
      });

      // Generated with https://dcpos.github.io/bip39/
      it('should fail to import from words if not at wallet service', function(done) {
        var exported = 'bounce tonight little spy earn void nominee ankle walk ten type update';
        importedClient = helpers.newClient(app);
        importedClient.importFromMnemonic(exported, {
          networkName: 'testnet',
        }, function(err) {
          err.should.be.an.instanceOf(Errors.UNAUTHORIZED);
          importedClient.mnemonicHasPassphrase().should.equal(false);
          importedClient.credentials.xPrivKey.should.equal('tprv8ZgxMBicQKsPdTYGTn3cPvTJJuuKHCYbfH1fbu4ceZ5tzYrcjYMKY1JfZiEFDDpEXWquSpX6jRsEoVPoaSw82tQ1Wn1U3K1bQDZBj3UGuEG');
          done();
        });
      });

      it('should fail to import from words if not at wallet service, with passphrase', function(done) {
        var exported = 'bounce tonight little spy earn void nominee ankle walk ten type update';
        importedClient = helpers.newClient(app);
        importedClient.importFromMnemonic(exported, {
          networkName: 'testnet',
          passphrase: 'hola',
        }, function(err) {
          err.should.be.an.instanceOf(Errors.UNAUTHORIZED);
          importedClient.mnemonicHasPassphrase().should.equal(true);
          importedClient.credentials.xPrivKey.should.equal('tprv8ZgxMBicQKsPdVijVxEu7gVDi86PUZqbCe7xTGLwVXwZpsG3HuxLDjXL3DXRSaaNymMD7gRpXimxnUDYa5N7pLTKLQymdSotrb4co7Nwrs7');
          done();
        });
      });
    });

    describe('Recovery', function() {
      it('should be able to gain access to a 1-1 wallet with just the xPriv', function(done) {
        helpers.createAndJoinWallet(clients, 1, 1, function() {
          var xpriv = clients[0].credentials.xPrivKey;
          var walletName = clients[0].credentials.walletName;
          var copayerName = clients[0].credentials.copayerName;

          clients[0].createAddress({}, function(err, addr) {
            should.not.exist(err);
            should.exist(addr);

            var recoveryClient = helpers.newClient(app);
            recoveryClient.seedFromExtendedPrivateKey(xpriv);
            recoveryClient.openWallet(function(err) {
              should.not.exist(err);
              recoveryClient.credentials.walletName.should.equal(walletName);
              recoveryClient.credentials.copayerName.should.equal(copayerName);
              recoveryClient.getMainAddresses({}, function(err, list) {
                should.not.exist(err);
                should.exist(list);
                list[0].address.should.equal(addr.address);
                done();
              });
            });
          });
        });
      });

      it('should be able to see txp messages after gaining access', function(done) {
        helpers.createAndJoinWallet(clients, 1, 1, function() {
          var xpriv = clients[0].credentials.xPrivKey;
          var walletName = clients[0].credentials.walletName;
          clients[0].createAddress({}, function(err, x0) {
            should.not.exist(err);
            should.exist(x0.address);
            blockchainExplorerMock.setUtxo(x0, 1, 1, 0);
            var opts = {
              amount: 30000,
              toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
              message: 'hello',
            };
            helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
              should.not.exist(err);
              var recoveryClient = helpers.newClient(app);
              recoveryClient.seedFromExtendedPrivateKey(xpriv);
              recoveryClient.openWallet(function(err) {
                should.not.exist(err);
                recoveryClient.credentials.walletName.should.equal(walletName);
                recoveryClient.getTx(x.id, function(err, x2) {
                  should.not.exist(err);
                  x2.message.should.equal(opts.message);
                  done();
                });
              });
            });
          });
        });
      });

      it('should be able to recreate wallet 2-2', function(done) {
        helpers.createAndJoinWallet(clients, 2, 2, function() {
          clients[0].createAddress({}, function(err, addr) {
            should.not.exist(err);
            should.exist(addr);

            var storage = new Storage({}, {
              db: helpers.newDb(),
            });

            var newApp;
            var expressApp = new ExpressApp(testConfig);
            expressApp.start({
              storage: storage,
              blockchainExplorer: blockchainExplorerMock
            }, function() {
              newApp = expressApp.app;

              var oldPKR = lodash.clone(clients[0].credentials.publicKeyRing);
              var recoveryClient = helpers.newClient(newApp);
              recoveryClient.import(clients[0].export());

              recoveryClient.getStatus({}, function(err, status) {
                should.exist(err);
                err.should.be.an.instanceOf(Errors.UNAUTHORIZED);
                var spy = sinon.spy(recoveryClient, '_doPostRequest');
                recoveryClient.recreateWallet(function(err) {
                  should.not.exist(err);

                  // Do not send wallet name and copayer names in clear text
                  var url = spy.getCall(0).args[0];
                  var body = JSON.stringify(spy.getCall(0).args[1]);
                  url.should.contain('/wallets');
                  body.should.not.contain('mywallet');
                  var url = spy.getCall(1).args[0];
                  var body = JSON.stringify(spy.getCall(1).args[1]);
                  url.should.contain('/copayers');
                  body.should.not.contain('creator');
                  body.should.not.contain('copayer 1');

                  recoveryClient.getStatus({}, function(err, status) {
                    should.not.exist(err);
                    status.wallet.name.should.equal('mywallet');
                    lodash.difference(lodash.map(status.wallet.copayers, 'name'), ['creator', 'copayer 1']).length.should.equal(0);
                    recoveryClient.createAddress({}, function(err, addr2) {
                      should.not.exist(err);
                      should.exist(addr2);
                      addr2.address.should.equal(addr.address);
                      addr2.path.should.equal(addr.path);

                      var recoveryClient2 = helpers.newClient(newApp);
                      recoveryClient2.import(clients[1].export());
                      recoveryClient2.getStatus({}, function(err, status) {
                        should.not.exist(err);
                        done();
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });

      it('should be able to recover funds from recreated wallet', function(done) {
        this.timeout(10000);
        helpers.createAndJoinWallet(clients, 2, 2, function() {
          clients[0].createAddress({}, function(err, addr) {
            should.not.exist(err);
            should.exist(addr);
            blockchainExplorerMock.setUtxo(addr, 1, 2);

            var storage = new Storage({}, {
              db: helpers.newDb(),
            });
            var newApp;
            var expressApp = new ExpressApp(testConfig);
            expressApp.start({
                storage: storage,
                blockchainExplorer: blockchainExplorerMock
              },
              function() {
                newApp = expressApp.app;

                var recoveryClient = helpers.newClient(newApp);
                recoveryClient.import(clients[0].export());

                recoveryClient.getStatus({}, function(err, status) {
                  should.exist(err);
                  err.should.be.an.instanceOf(Errors.UNAUTHORIZED);
                  recoveryClient.recreateWallet(function(err) {
                    should.not.exist(err);
                    recoveryClient.getStatus({}, function(err, status) {
                      should.not.exist(err);
                      recoveryClient.startScan({}, function(err) {
                        should.not.exist(err);
                        var balance = 0;
                        async.whilst(function() {
                          return balance == 0;
                        }, function(next) {
                          setTimeout(function() {
                            recoveryClient.getBalance({}, function(err, b) {
                              balance = b.totalAmount;
                              next(err);
                            });
                          }, 200);
                        }, function(err) {
                          should.not.exist(err);
                          balance.should.equal(1e8);
                          done();
                        });
                      });
                    });
                  });
                });
              });
          });
        });
      });

      it('should be able call recreate wallet twice', function(done) {
        helpers.createAndJoinWallet(clients, 2, 2, function() {
          clients[0].createAddress({}, function(err, addr) {
            should.not.exist(err);
            should.exist(addr);

            var storage = new Storage({}, {
              db: helpers.newDb(),
            });
            var newApp;
            var expressApp = new ExpressApp(testConfig);
            expressApp.start({
                storage: storage,
                blockchainExplorer: blockchainExplorerMock
              },
              function() {
                newApp = expressApp.app;

                var oldPKR = lodash.clone(clients[0].credentials.publicKeyRing);
                var recoveryClient = helpers.newClient(newApp);
                recoveryClient.import(clients[0].export());

                recoveryClient.getStatus({}, function(err, status) {
                  should.exist(err);
                  err.should.be.an.instanceOf(Errors.UNAUTHORIZED);
                  recoveryClient.recreateWallet(function(err) {
                    should.not.exist(err);
                    recoveryClient.recreateWallet(function(err) {
                      should.not.exist(err);
                      recoveryClient.getStatus({}, function(err, status) {
                        should.not.exist(err);
                        lodash.difference(lodash.map(status.wallet.copayers, 'name'), ['creator', 'copayer 1']).length.should.equal(0);
                        recoveryClient.createAddress({}, function(err, addr2) {
                          should.not.exist(err);
                          should.exist(addr2);
                          addr2.address.should.equal(addr.address);
                          addr2.path.should.equal(addr.path);

                          var recoveryClient2 = helpers.newClient(newApp);
                          recoveryClient2.import(clients[1].export());
                          recoveryClient2.getStatus({}, function(err, status) {
                            should.not.exist(err);
                            done();
                          });
                        });
                      });
                    });
                  });
                });
              });
          });
        });
      });

      it('should be able to recreate 1-of-1 wallet with external key (m/48) account 2', function(done) {
        clients[0].seedFromExtendedPublicKey('tpubD6NzVbkrYhZ4XJEQQWBgysPKJcBv8zLhHpfhcw4RyhakMxmffNRRRFDUe1Zh7fxvjt1FdNJcaxHgqxyKLL8XiZug7C8KJFLFtGfPVBcY6Nb', 'ledger', 'b0937662dddea83b0ce037ff3991dd', {
          account: 2,
          derivationStrategy: 'BIP48',
        });
        clients[0].createWallet('mywallet', 'creator', 1, 1, {
          networkName: 'testnet'
        }, function(err, secret) {
          should.not.exist(err);

          clients[0].createAddress({}, function(err, addr) {
            should.not.exist(err);
            should.exist(addr);

            var storage = new Storage({}, {
              db: helpers.newDb(),
            });

            var newApp;
            var expressApp = new ExpressApp(testConfig);
            expressApp.start({
              storage: storage,
              blockchainExplorer: blockchainExplorerMock
            }, function() {
              newApp = expressApp.app;

              var oldPKR = lodash.clone(clients[0].credentials.publicKeyRing);
              var recoveryClient = helpers.newClient(newApp);
              recoveryClient.import(clients[0].export());
              recoveryClient.credentials.derivationStrategy.should.equal('BIP48');
              recoveryClient.credentials.account.should.equal(2);
              recoveryClient.getStatus({}, function(err, status) {
                should.exist(err);
                err.should.be.an.instanceOf(Errors.UNAUTHORIZED);
                recoveryClient.recreateWallet(function(err) {
                  should.not.exist(err);
                  recoveryClient.getStatus({}, function(err, status) {
                    should.not.exist(err);
                    recoveryClient.createAddress({}, function(err, addr2) {
                      should.not.exist(err);
                      should.exist(addr2);
                      addr2.address.should.equal(addr.address);
                      addr2.path.should.equal(addr.path);
                      done();
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  });

  describe('Air gapped related flows', function() {
    it('should create wallet in proxy from airgapped', function(done) {
      var airgapped = new WalletClient.API();
      airgapped.seedFromRandom({
        networkName: 'testnet'
      });
      var exported = airgapped.export({
        noSign: true
      });

      var proxy = helpers.newClient(app);
      proxy.import(exported);
      should.not.exist(proxy.credentials.xPrivKey);

      var seedSpy = sinon.spy(proxy, 'seedFromRandom');
      proxy.createWallet('mywallet', 'creator', 1, 1, {
        networkName: 'testnet'
      }, function(err) {
        should.not.exist(err);
        seedSpy.called.should.be.false;
        proxy.getStatus({}, function(err, status) {
          should.not.exist(err);
          status.wallet.name.should.equal('mywallet');
          done();
        });
      });
    });

    it('should fail to create wallet in proxy from airgapped when networks do not match', function(done) {
      var airgapped = new WalletClient.API();
      airgapped.seedFromRandom({
        networkName: 'testnet'
      });
      var exported = airgapped.export({
        noSign: true
      });

      var proxy = helpers.newClient(app);
      proxy.import(exported);
      should.not.exist(proxy.credentials.xPrivKey);

      var seedSpy = sinon.spy(proxy, 'seedFromRandom');
      should.not.exist(proxy.credentials.xPrivKey);
      proxy.createWallet('mywallet', 'creator', 1, 1, {
        networkName: 'btc'
      }, function(err) {
        should.exist(err);
        err.message.should.equal('Existing keys were created for a different network');
        done();
      });
    });

    it('should be able to sign from airgapped client and broadcast from proxy', function(done) {
      var airgapped = new WalletClient.API();
      airgapped.seedFromRandom({
        networkName: 'testnet'
      });
      var exported = airgapped.export({
        noSign: true
      });

      var proxy = helpers.newClient(app);
      proxy.import(exported);
      should.not.exist(proxy.credentials.xPrivKey);

      async.waterfall([

          function(next) {
            proxy.createWallet('mywallet', 'creator', 1, 1, {
              networkName: 'testnet'
            }, function(err) {
              should.not.exist(err);
              proxy.createAddress({}, function(err, address) {
                should.not.exist(err);
                should.exist(address.address);
                blockchainExplorerMock.setUtxo(address, 1, 1);
                var opts = {
                  amount: 1200000,
                  toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
                  message: 'hello 1-1',
                };
                helpers.createAndPublishTxProposal(proxy, opts, next);
              });
            });
          },
          function(txp, next) {
            should.exist(txp);
            proxy.signTxProposal(txp, function(err, txp) {
              should.exist(err);
              should.not.exist(txp);
              err.message.should.equal('Missing private keys to sign.');
              next(null, txp);
            });
          },
          function(txp, next) {
            proxy.getTxProposals({
              forAirGapped: true
            }, next);
          },
          function(bundle, next) {
            var signatures = airgapped.signTxProposalFromAirGapped(bundle.txps[0], bundle.encryptedPkr, bundle.m, bundle.n);
            next(null, signatures);
          },
          function(signatures, next) {
            proxy.getTxProposals({}, function(err, txps) {
              should.not.exist(err);
              var txp = txps[0];
              txp.signatures = signatures;
              async.each(txps, function(txp, cb) {
                proxy.signTxProposal(txp, function(err, txp) {
                  should.not.exist(err);
                  proxy.broadcastTxProposal(txp, function(err, txp) {
                    should.not.exist(err);
                    txp.status.should.equal('broadcasted');
                    should.exist(txp.txid);
                    cb();
                  });
                });
              }, function(err) {
                next(err);
              });
            });
          },
        ],
        function(err) {
          should.not.exist(err);
          done();
        }
      );
    });

    it('should be able to sign from airgapped client with mnemonics (with unencrypted xpubkey ring)', function(done) {
      var client = helpers.newClient(app);
      client.seedFromRandomWithMnemonic({
        networkName: 'testnet',
        passphrase: 'passphrase',
      });

      var mnemonic = client.getMnemonic();
      client.encryptPrivateKey('password');
      client.isPrivKeyEncrypted().should.be.true;

      async.waterfall([

          function(next) {
            client.createWallet('mywallet', 'creator', 1, 1, {
              networkName: 'testnet'
            }, function(err) {
              should.not.exist(err);
              client.createAddress({}, function(err, address) {
                should.not.exist(err);
                should.exist(address.address);
                blockchainExplorerMock.setUtxo(address, 1, 1);
                var opts = {
                  amount: 1200000,
                  toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
                  message: 'hello 1-1',
                };
                helpers.createAndPublishTxProposal(client, opts, next);
              });
            });
          },
          function(txp, next) {
            should.exist(txp);
            client.getTxProposals({
              forAirGapped: true,
              doNotEncryptPkr: true,
            }, next);
          },
          function(bundle, next) {
            var signatures = client.signTxProposalFromAirGapped(bundle.txps[0], bundle.unencryptedPkr, bundle.m, bundle.n, 'password');
            next(null, signatures);
          },
          function(signatures, next) {
            client.getTxProposals({}, function(err, txps) {
              should.not.exist(err);
              var txp = txps[0];
              txp.signatures = signatures;
              async.each(txps, function(txp, cb) {
                client.signTxProposal(txp, function(err, txp) {
                  should.not.exist(err);
                  client.broadcastTxProposal(txp, function(err, txp) {
                    should.not.exist(err);
                    txp.status.should.equal('broadcasted');
                    should.exist(txp.txid);
                    cb();
                  });
                });
              }, function(err) {
                next(err);
              });
            });
          },
        ],
        function(err) {
          should.not.exist(err);
          done();
        }
      );
    });

    describe('Failure and tampering', function() {
      var airgapped, proxy, bundle;

      beforeEach(function(done) {
        airgapped = new WalletClient.API();
        airgapped.seedFromRandom({
          networkName: 'testnet'
        });
        var exported = airgapped.export({
          noSign: true
        });

        proxy = helpers.newClient(app);
        proxy.import(exported);
        should.not.exist(proxy.credentials.xPrivKey);

        async.waterfall([

            function(next) {
              proxy.createWallet('mywallet', 'creator', 1, 1, {
                networkName: 'testnet'
              }, function(err) {
                should.not.exist(err);
                proxy.createAddress({}, function(err, address) {
                  should.not.exist(err);
                  should.exist(address.address);
                  blockchainExplorerMock.setUtxo(address, 1, 1);
                  var opts = {
                    amount: 1200000,
                    toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
                    message: 'hello 1-1',
                  };
                  helpers.createAndPublishTxProposal(proxy, opts, next);
                });
              });
            },
            function(txp, next) {
              proxy.getTxProposals({
                forAirGapped: true
              }, function(err, result) {
                should.not.exist(err);
                bundle = result;
                next();
              });
            },
          ],
          function(err) {
            should.not.exist(err);
            done();
          }
        );
      });

      it('should fail to sign from airgapped client when there is no extended private key', function(done) {
        delete airgapped.credentials.xPrivKey;
        (function() {
          airgapped.signTxProposalFromAirGapped(bundle.txps[0], bundle.encryptedPkr, bundle.m, bundle.n);
        }).should.throw('Missing private keys');
        done();
      });

      it('should fail gracefully when PKR cannot be decrypted in airgapped client', function(done) {
        bundle.encryptedPkr = 'dummy';
        (function() {
          airgapped.signTxProposalFromAirGapped(bundle.txps[0], bundle.encryptedPkr, bundle.m, bundle.n);
        }).should.throw('Could not decrypt public key ring');
        done();
      });

      it('should be able to detect invalid or tampered PKR when signing on airgapped client', function(done) {
        (function() {
          airgapped.signTxProposalFromAirGapped(bundle.txps[0], bundle.encryptedPkr, bundle.m, 2);
        }).should.throw('Invalid public key ring');
        done();
      });

      it.skip('should be able to detect tampered proposal when signing on airgapped client', function(done) {
        bundle.txps[0].encryptedMessage = 'tampered message';
        (function() {
          airgapped.signTxProposalFromAirGapped(bundle.txps[0], bundle.encryptedPkr, bundle.m, bundle.n);
        }).should.throw('Fake transaction proposal');
        done();
      });

      it('should be able to detect tampered change address when signing on airgapped client', function(done) {
        bundle.txps[0].changeAddress.address = 'mqNkvNuhzZKeXYNRZ1bdj55smmW3acr6K7';
        (function() {
          airgapped.signTxProposalFromAirGapped(bundle.txps[0], bundle.encryptedPkr, bundle.m, bundle.n);
        }).should.throw('Fake transaction proposal');
        done();
      });
    });
  });

  describe('Private key encryption', function() {
    var password = 'jesusissatoshi';
    var c1, c2;
    var importedClient;

    beforeEach(function(done) {
      c1 = clients[1];
      clients[1].seedFromRandomWithMnemonic({
        networkName: 'testnet'
      });
      clients[1].createWallet('mywallet', 'creator', 1, 1, {
        networkName: 'testnet',
      }, function() {
        clients[1].encryptPrivateKey(password);
        done();
      });
    });

    it('should fail to decrypt if not encrypted', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        (function() {
          clients[0].decryptPrivateKey('wrong');
        }).should.throw('encrypted');
        done();
      });
    });

    it('should return priv key is not encrypted', function(done) {
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        clients[0].isPrivKeyEncrypted().should.be.false;
        done();
      });
    });

    it('should return priv key is encrypted', function() {
      c1.isPrivKeyEncrypted().should.be.true;
    });

    it('should prevent to reencrypt the priv key', function() {
      (function() {
        c1.encryptPrivateKey('pepe');
      }).should.throw('Private key already encrypted');
    });

    it('should allow to decrypt', function() {
      c1.decryptPrivateKey(password);
      c1.isPrivKeyEncrypted().should.be.false;
    });

    it('should prevent to encrypt airgapped\'s proxy credentials', function() {
      var airgapped = new WalletClient.API();
      airgapped.seedFromRandom({
        networkName: 'testnet'
      });
      var exported = airgapped.export({
        noSign: true
      });
      var proxy = helpers.newClient(app);
      proxy.import(exported);
      should.not.exist(proxy.credentials.xPrivKey);
      (function() {
        proxy.encryptPrivateKey('pepe');
      }).should.throw('No private key');
    });

    it('should not contain unencrypted fields when encrypted', function() {
      var keys = c1.getKeys(password);
      c1.isPrivKeyEncrypted().should.be.true;
      var str = JSON.stringify(c1.credentials);
      str.indexOf(keys.xPrivKey).should.equal(-1);
      str.indexOf(keys.mnemonic).should.equal(-1);
    });

    it('should restore cleartext fields when decrypting', function() {
      var keys = c1.getKeys(password);
      (function() {
        c1.getMnemonic();
      }).should.throw('encrypted');
      c1.decryptPrivateKey(password);
      c1.credentials.xPrivKey.should.equal(keys.xPrivKey);
      c1.getMnemonic().should.equal(keys.mnemonic);
    });

    it('should fail to decrypt with wrong password', function() {
      (function() {
        c1.decryptPrivateKey('wrong')
      }).should.throw('Could not decrypt');
    });

    it('should export & import encrypted', function(done) {
      var walletId = c1.credentials.walletId;
      var walletName = c1.credentials.walletName;
      var copayerName = c1.credentials.copayerName;
      var exported = c1.export({});
      importedClient = helpers.newClient(app);
      importedClient.import(exported, {});
      importedClient.openWallet(function(err) {
        should.not.exist(err);
        importedClient.credentials.walletId.should.equal(walletId);
        importedClient.credentials.walletName.should.equal(walletName);
        importedClient.credentials.copayerName.should.equal(copayerName);
        importedClient.isPrivKeyEncrypted().should.equal(true);
        importedClient.decryptPrivateKey(password);
        importedClient.isPrivKeyEncrypted().should.equal(false);
        done();
      });
    });

    it('should check right password', function() {
      var valid = c1.checkPassword(password);
      valid.should.equal(true);
    });

    it('should failt to check wrong password', function() {
      var valid = c1.checkPassword('x');
      valid.should.equal(false);
    });

    it('should fail to sign when encrypted and no password is provided', function(done) {
      c1.createAddress({}, function(err, x0) {
        should.not.exist(err);
        blockchainExplorerMock.setUtxo(x0, 1, 1);
        var opts = {
          amount: 10000000,
          toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
          message: 'hello 1-1',
        };
        helpers.createAndPublishTxProposal(c1, opts, function(err, txp) {
          should.not.exist(err);
          c1.signTxProposal(txp, function(err) {
            err.message.should.contain('encrypted');
            done();
          });
        });
      });
    });

    it('should sign when encrypted and password provided', function(done) {
      c1.createAddress({}, function(err, x0) {
        should.not.exist(err);
        blockchainExplorerMock.setUtxo(x0, 1, 1);
        var opts = {
          amount: 10000000,
          toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
          message: 'hello 1-1',
        };
        helpers.createAndPublishTxProposal(c1, opts, function(err, txp) {
          should.not.exist(err);
          c1.signTxProposal(txp, password, function(err) {
            should.not.exist(err);
            c1.isPrivKeyEncrypted().should.be.true;
            done();
          });
        });
      });
    });

    it('should fail to sign when encrypted and incorrect password', function(done) {
      c1.createAddress({}, function(err, x0) {
        should.not.exist(err);
        blockchainExplorerMock.setUtxo(x0, 1, 1);
        var opts = {
          amount: 10000000,
          toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
          message: 'hello 1-1',
        };
        helpers.createAndPublishTxProposal(c1, opts, function(err, txp) {
          should.not.exist(err);
          c1.signTxProposal(txp, 'wrong', function(err) {
            err.message.should.contain('not decrypt');
            done();
          });
        });
      });
    });
  });

  describe('#addAccess', function() {
    describe('1-1 wallets', function() {
      var opts;

      beforeEach(function(done) {
        opts = {
          amount: 10000,
          toAddress: 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5',
          message: 'hello',
        };

        helpers.createAndJoinWallet(clients, 1, 1, function() {
          clients[0].createAddress({}, function(err, x0) {
            should.not.exist(err);
            blockchainExplorerMock.setUtxo(x0, 10, 1);
            var c = clients[0].credentials;

            // Ggenerate a new priv key, not registered
            var k = new PrivateKey();
            c.requestPrivKey = k.toString();
            c.requestPubKey = k.toPublicKey().toString();
            done();
          });
        });
      });

      it('should deny access before registering it ', function(done) {
        helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
          err.should.be.an.instanceOf(Errors.UNAUTHORIZED);
          done();
        });
      });

      it('should grant access with current keys', function(done) {
        clients[0].addAccess({}, function(err, x) {
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
            should.not.exist(err);
            done();
          });
        });
      });

      it('should add access with copayer name', function(done) {
        var spy = sinon.spy(clients[0], '_doPutRequest');
        clients[0].addAccess({
          name: 'pepe',
        }, function(err, x, key) {
          should.not.exist(err);
          var url = spy.getCall(0).args[0];
          var body = JSON.stringify(spy.getCall(0).args[1]);
          url.should.contain('/copayers');
          body.should.not.contain('pepe');

          var k = new PrivateKey(key);
          var c = clients[0].credentials;
          c.requestPrivKey = k.toString();
          c.requestPubKey = k.toPublicKey().toString();

          clients[0].getStatus({}, function(err, status) {
            should.not.exist(err);
            var keys = status.wallet.copayers[0].requestPubKeys;
            keys.length.should.equal(2);
            lodash.filter(keys, {
              name: 'pepe'
            }).length.should.equal(1);

            helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
              should.not.exist(err);
              // TODO: verify tx's creator is 'pepe'
              done();
            });
          });
        });
      });

      it('should grant access with *new* keys then deny access with old keys', function(done) {
        clients[0].addAccess({
          generateNewKey: true
        }, function(err, x) {
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
            err.should.be.an.instanceOf(Errors.UNAUTHORIZED);
            done();
          });
        });
      });

      it('should grant access with new keys', function(done) {
        clients[0].addAccess({
          generateNewKey: true
        }, function(err, x, key) {
          var k = new PrivateKey(key);
          var c = clients[0].credentials;
          c.requestPrivKey = k.toString();
          c.requestPubKey = k.toPublicKey().toString();
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
            should.not.exist(err);
            done();
          });
        });
      });

      it('should verify tx proposals of added access', function(done) {
        clients[0].addAccess({}, function(err, x) {
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
            should.not.exist(err);
            clients[0].getTxProposals({}, function(err, txps) {
              should.not.exist(err);
              done();
            });
          });
        });
      });

      it('should detect tampered tx proposals of added access (case 1)', function(done) {
        clients[0].addAccess({}, function(err, x) {
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
            should.not.exist(err);
            helpers.tamperResponse(clients[0], 'get', '/v1/txproposals/', {}, function(txps) {
              txps[0].proposalSignature = '304402206e4a1db06e00068582d3be41cfc795dcf702451c132581e661e7241ef34ca19202203e17598b4764913309897d56446b51bc1dcd41a25d90fdb5f87a6b58fe3a6920';
            }, function() {
              clients[0].getTxProposals({}, function(err, txps) {
                err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
                done();
              });
            });
          });
        });
      });

      it('should detect tampered tx proposals of added access (case 2)', function(done) {
        clients[0].addAccess({}, function(err, x) {
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
            should.not.exist(err);
            helpers.tamperResponse(clients[0], 'get', '/v1/txproposals/', {}, function(txps) {
              txps[0].proposalSignaturePubKey = '02d368d7f03a57b2ad3ad9c2766739da83b85ab9c3718fb02ad36574f9391d6bf6';
            }, function() {
              clients[0].getTxProposals({}, function(err, txps) {
                err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
                done();
              });
            });
          });
        });
      });

      it('should detect tampered tx proposals of added access (case 3)', function(done) {
        clients[0].addAccess({}, function(err, x) {
          helpers.createAndPublishTxProposal(clients[0], opts, function(err, x) {
            should.not.exist(err);
            helpers.tamperResponse(clients[0], 'get', '/v1/txproposals/', {}, function(txps) {
              txps[0].proposalSignaturePubKeySig = '304402201528748eafc5083fe67c84cbf0eb996eba9a65584a73d8c07ed6e0dc490c195802204f340488266c804cf1033f8b852efd1d4e05d862707c119002dc3fbe7a805c35';
            }, function() {
              clients[0].getTxProposals({}, function(err, txps) {
                err.should.be.an.instanceOf(Errors.SERVER_COMPROMISED);
                done();
              });
            });
          });
        });
      });
    });
  });

  describe('Sweep paper wallet', function() {
    it('should decrypt bip38 encrypted private key', function(done) {
      this.timeout(60000);
      clients[0].decryptBIP38PrivateKey('6PfRh9ZnWtiHrGoPPSzXe6iafTXc6FSXDhSBuDvvDmGd1kpX2Gvy1CfTcA', 'passphrase', {}, function(err, result) {
        should.not.exist(err);
        result.should.equal('5KjBgBiadWGhjWmLN1v4kcEZqWSZFqzgv7cSUuZNJg4tD82c4xp');
        done();
      });
    });

    it('should fail to decrypt bip38 encrypted private key with incorrect passphrase', function(done) {
      this.timeout(60000);
      clients[0].decryptBIP38PrivateKey('6PfRh9ZnWtiHrGoPPSzXe6iafTXc6FSXDhSBuDvvDmGd1kpX2Gvy1CfTcA', 'incorrect passphrase', {}, function(err, result) {
        should.exist(err);
        err.message.should.contain('passphrase');
        done();
      });
    });

    it('should get balance from single private key', function(done) {
      var address = {
        address: '1PuKMvRFfwbLXyEPXZzkGi111gMUCs6uE3',
        type: 'P2PKH',
      };
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        blockchainExplorerMock.setUtxo(address, 123, 1);
        clients[0].getBalanceFromPrivateKey('5KjBgBiadWGhjWmLN1v4kcEZqWSZFqzgv7cSUuZNJg4tD82c4xp', function(err, balance) {
          should.not.exist(err);
          balance.should.equal(123 * 1e8);
          done();
        });
      });
    });

    it('should build tx for single private key', function(done) {
      var address = {
        address: '1PuKMvRFfwbLXyEPXZzkGi111gMUCs6uE3',
        type: 'P2PKH',
      };
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        blockchainExplorerMock.setUtxo(address, 123, 1);
        clients[0].buildTxFromPrivateKey('5KjBgBiadWGhjWmLN1v4kcEZqWSZFqzgv7cSUuZNJg4tD82c4xp', '1GG3JQikGC7wxstyavUBDoCJ66bWLLENZC', {}, function(err, tx) {
          should.not.exist(err);
          should.exist(tx);
          tx.outputs.length.should.equal(1);
          var output = tx.outputs[0];
          output.satoshis.should.equal(123 * 1e8 - 10000);
          var script = new Script.buildPublicKeyHashOut(Address.fromString('1GG3JQikGC7wxstyavUBDoCJ66bWLLENZC'));
          output.script.toString('hex').should.equal(script.toString('hex'));
          done();
        });
      });
    });

    it('should handle tx serialization error when building tx', function(done) {
      var sandbox = sinon.sandbox.create();

      var se = sandbox.stub(Transaction.prototype, 'serialize', function() {
        throw new Error('this is an error');
      });

      var address = {
        address: '1PuKMvRFfwbLXyEPXZzkGi111gMUCs6uE3',
        type: 'P2PKH',
      };
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        blockchainExplorerMock.setUtxo(address, 123, 1);
        clients[0].buildTxFromPrivateKey('5KjBgBiadWGhjWmLN1v4kcEZqWSZFqzgv7cSUuZNJg4tD82c4xp', '1GG3JQikGC7wxstyavUBDoCJ66bWLLENZC', {}, function(err, tx) {
          should.exist(err);
          should.not.exist(tx);
          err.should.be.an.instanceOf(Errors.COULD_NOT_BUILD_TRANSACTION);
          sandbox.restore();
          done();
        });
      });
    });

    it('should fail to build tx for single private key if insufficient funds', function(done) {
      var address = {
        address: '1PuKMvRFfwbLXyEPXZzkGi111gMUCs6uE3',
        type: 'P2PKH',
      };
      helpers.createAndJoinWallet(clients, 1, 1, function() {
        blockchainExplorerMock.setUtxo(address, 123 / 1e8, 1);
        clients[0].buildTxFromPrivateKey('5KjBgBiadWGhjWmLN1v4kcEZqWSZFqzgv7cSUuZNJg4tD82c4xp', '1GG3JQikGC7wxstyavUBDoCJ66bWLLENZC', {
          fee: 500
        }, function(err, tx) {
          should.exist(err);
          err.should.be.an.instanceOf(Errors.INSUFFICIENT_FUNDS);
          done();
        });
      });
    });
  });

  describe('#formatAmount', function() {
    it('should successfully format amount', function() {
      var cases = [{
        args: {
          amount: 1,
          code: 'bit',
          opts: {
            includeUnits: false
          }
        },
        expected: '0'
      }, {
        args: {
          amount: 1,
          code: 'BTC',
          opts: {
            includeUnits: false
          }
        },
        expected: '0.00'
      }, {
        args: {
          amount: 0,
          code: 'bit',
          opts: {
            includeUnits: false
          }
        },
        expected: '0'
      }, {
        args: {
          amount: 12345678,
          code: 'bit',
          opts: {
            includeUnits: false
          }
        },
        expected: '123,457'
      }, {
        args: {
          amount: 12345678,
          code: 'BTC',
          opts: {
            includeUnits: false
          }
        },
        expected: '0.123457'
      }, {
        args: {
          amount: 12345611,
          code: 'BTC',
          opts: {
            includeUnits: false
          }
        },
        expected: '0.123456'
      }, {
        args: {
          amount: 1234,
          code: 'BTC',
          opts: {
            includeUnits: false
          }
        },
        expected: '0.000012'
      }, {
        args: {
          amount: 1299,
          code: 'BTC',
          opts: {
            includeUnits: false
          }
        },
        expected: '0.000013'
      }, {
        args: {
          amount: 1234567899999,
          code: 'BTC',
          opts: {
            includeUnits: false
          }
        },
        expected: '12,345.679'
      }, {
        args: {
          amount: 12345678,
          code: 'bit',
          opts: {
            includeUnits: false,
            thousandsSeparator: '.'
          }
        },
        expected: '123.457'
      }, {
        args: {
          amount: 12345678,
          code: 'BTC',
          opts: {
            includeUnits: false,
            decimalSeparator: ','
          }
        },
        expected: '0,123457'
      }, {
        args: {
          amount: 1234567899999,
          code: 'BTC',
          opts: {
            includeUnits: false,
            thousandsSeparator: ' ',
            decimalSeparator: ','
          }
        },
        expected: '12 345,679'
      }, {
        args: {
          amount: 12345678,
          code: 'bit',
          opts: {
            includeUnits: true,
            thousandsSeparator: '.'
          }
        },
        expected: '123.457 bits'
      }, {
        args: {
          amount: 12345678,
          code: 'BTC',
          opts: {
            includeUnits: true,
            decimalSeparator: ','
          }
        },
        expected: '0,123457 BTC'
      }];

      lodash.each(cases, function(testCase) {
        var amount = new WalletClient.API().formatAmount(testCase.args.amount, testCase.args.code, testCase.args.opts);
        amount.should.equal(testCase.expected);
      });
    });
  });

  describe('_initNotifications', function() {
    it('should handle NOT_FOUND error from _fetchLatestNotifications', function(done) {
      var sandbox = sinon.sandbox.create();
      var clock = sandbox.useFakeTimers();

      var client = new WalletClient.API();

      var _f = sandbox.stub(client, '_fetchLatestNotifications', function(interval, cb) {
        cb(new Errors.NOT_FOUND);
      });

      client._initNotifications({
        notificationIntervalSeconds: 1
      });
      should.exist(client.notificationsIntervalId);
      clock.tick(1000);
      should.not.exist(client.notificationsIntervalId);
      sandbox.restore();
      done();
    });

    it('should handle UNAUTHORIZED error from _fetLatestNotifications', function(done) {
      var sandbox = sinon.sandbox.create();
      var clock = sandbox.useFakeTimers();

      var client = new WalletClient.API();

      var _f = sandbox.stub(client, '_fetchLatestNotifications', function(interval, cb) {
        cb(new Errors.UNAUTHORIZED);
      });

      client._initNotifications({
        notificationIntervalSeconds: 1
      });
      should.exist(client.notificationsIntervalId);
      clock.tick(1000);
      should.not.exist(client.notificationsIntervalId);
      sandbox.restore();
      done();
    });
  });

  describe('Import', function() {
    describe('#import', function(done) {
      it('should handle import with invalid JSON', function(done) {
        var importString = 'this is not valid JSON';
        var client = new WalletClient.API();
        (function() {
          client.import(importString);
        }).should.throw(Errors.INVALID_BACKUP);
        done();
      });
    });

    describe('#_import', function() {
      it('should handle not being able to add access', function(done) {
        var sandbox = sinon.sandbox.create();
        var client = new WalletClient.API();
        client.credentials = {};

        var ow = sandbox.stub(client, 'openWallet', function(callback) {
          callback(new Error());
        });

        var ip = sandbox.stub(client, 'isPrivKeyExternal', function() {
          return false;
        });

        var aa = sandbox.stub(client, 'addAccess', function(options, callback) {
          callback(new Error());
        });

        client._import(function(err) {
          should.exist(err);
          err.should.be.an.instanceOf(Errors.WALLET_DOES_NOT_EXIST);
          sandbox.restore();
          done();
        });
      });
    });

    describe('#importFromMnemonic', function() {
      it('should handle importing an invalid mnemonic', function(done) {
        var client = new WalletClient.API();
        var mnemonicWords = 'this is an invalid mnemonic';
        client.importFromMnemonic(mnemonicWords, {}, function(err) {
          should.exist(err);
          err.should.be.an.instanceOf(Errors.INVALID_BACKUP);
          done();
        });
      });
    });

    describe('#importFromExtendedPrivateKey', function() {
      it('should handle importing an invalid extended private key', function(done) {
        var client = new WalletClient.API();
        var xPrivKey = 'this is an invalid key';
        client.importFromExtendedPrivateKey(xPrivKey, {}, function(err) {
          should.exist(err);
          err.should.be.an.instanceOf(Errors.INVALID_BACKUP);
          done();
        });
      });
    });

    describe('#importFromExtendedPublicKey', function() {
      it('should handle importing an invalid extended private key', function(done) {
        var client = new WalletClient.API();
        var xPubKey = 'this is an invalid key';
        client.importFromExtendedPublicKey(xPubKey, {}, {}, {}, function(err) {
          should.exist(err);
          err.should.be.an.instanceOf(Errors.INVALID_BACKUP);
          done();
        });
      });
    });

    it('should import with external priv key', function(done) {
      var client = helpers.newClient(app);
      client.seedFromExtendedPublicKey('xpub661MyMwAqRbcGVyYUcHbZi9KNhN9Tdj8qHi9ZdoUXP1VeKiXDGGrE9tSoJKYhGFE2rimteYdwvoP6e87zS5LsgcEvsvdrpPBEmeWz9EeAUq', 'ledger', '1a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f00');
      client.createWallet('mywallet', 'creator', 1, 1, {
        networkName: 'btc'
      }, function(err) {
        should.not.exist(err);
        var c = client.credentials;
        var importedClient = helpers.newClient(app);
        importedClient.importFromExtendedPublicKey('xpub661MyMwAqRbcGVyYUcHbZi9KNhN9Tdj8qHi9ZdoUXP1VeKiXDGGrE9tSoJKYhGFE2rimteYdwvoP6e87zS5LsgcEvsvdrpPBEmeWz9EeAUq', 'ledger', '1a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f001a1f00', {}, function(err) {
          should.not.exist(err);
          var c2 = importedClient.credentials;
          c2.account.should.equal(0);
          c2.xPubKey.should.equal(client.credentials.xPubKey);
          c2.personalEncryptingKey.should.equal(c.personalEncryptingKey);
          c2.walletId.should.equal(c.walletId);
          c2.walletName.should.equal(c.walletName);
          c2.copayerName.should.equal(c.copayerName);
          done();
        });
      });
    });

    it('should fail to import with external priv key when not enought entropy', function() {
      var client = helpers.newClient(app);
      (function() {
        client.seedFromExtendedPublicKey('xpub661MyMwAqRbcGVyYUcHbZi9KNhN9Tdj8qHi9ZdoUXP1VeKiXDGGrE9tSoJKYhGFE2rimteYdwvoP6e87zS5LsgcEvsvdrpPBEmeWz9EeAUq', 'ledger', '1a1f00');
      }).should.throw('entropy');
    });
  });

  describe('_doRequest', function() {
    it('should handle connection error', function(done) {
      var client = new WalletClient.API();
      client.credentials = {};
      client.request = helpers.stubRequest(null, {});
      client._doRequest('get', 'url', {}, false, function(err, body, header) {
        should.exist(err);
        should.not.exist(body);
        should.not.exist(header);
        err.should.be.an.instanceOf(Errors.CONNECTION_ERROR);
        done();
      });
    });

    it('should handle ECONNRESET error', function(done) {
      var client = new WalletClient.API();
      client.credentials = {};
      client.request = helpers.stubRequest(null, {
        status: 200,
        body: '{"error":"read ECONNRESET"}',
      });
      client._doRequest('get', 'url', {}, false, function(err, body, header) {
        should.exist(err);
        should.not.exist(body);
        should.not.exist(header);
        err.should.be.an.instanceOf(Errors.ECONNRESET_ERROR);
        done();
      });
    });
  });

  describe('Single-address wallets', function() {
    beforeEach(function(done) {
      helpers.createAndJoinWallet(clients, 1, 2, {
        singleAddress: true
      }, function(wallet) {
        done();
      });
    });

    it('should always return same address', function(done) {
      clients[0].createAddress({}, function(err, x) {
        should.not.exist(err);
        should.exist(x);
        x.path.should.equal('m/0/0');
        clients[0].createAddress({}, function(err, y) {
          should.not.exist(err);
          should.exist(y);
          y.path.should.equal('m/0/0');
          y.address.should.equal(x.address);
          clients[1].createAddress({}, function(err, z) {
            should.not.exist(err);
            should.exist(z);
            z.path.should.equal('m/0/0');
            z.address.should.equal(x.address);
            clients[0].getMainAddresses({}, function(err, addr) {
              should.not.exist(err);
              addr.length.should.equal(1);
              done();
            });
          });
        });
      });
    });

    it('should reuse address as change address on tx proposal creation', function(done) {
      clients[0].createAddress({}, function(err, address) {
        should.not.exist(err);
        should.exist(address.address);
        blockchainExplorerMock.setUtxo(address, 2, 1);

        var toAddress = 'n2TBMPzPECGUfcT2EByiTJ12TPZkhN2mN5';
        var opts = {
          outputs: [{
            amount: 1e8,
            toAddress: toAddress,
          }],
          feePerKb: 100e2,
        };
        clients[0].createTxProposal(opts, function(err, txp) {
          should.not.exist(err);
          should.exist(txp);
          should.exist(txp.changeAddress);
          txp.changeAddress.address.should.equal(address.address);
          txp.changeAddress.path.should.equal(address.path);
          done();
        });
      });
    });
  });
});
