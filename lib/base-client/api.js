'use strict';

var owsCommon = require('@owstack/ows-common');
var keyLib = require('@owstack/key-lib');
var async = require('async');
var Base58 = owsCommon.encoding.Base58;
var Base58Check = owsCommon.encoding.Base58Check;
var Bip38 = require('bip38');
var Constants = owsCommon.Constants;
var Credentials = require('@owstack/credentials-lib');
var Errors = require('./errors');
var EventEmitter = require('events').EventEmitter;
var Hash = owsCommon.Hash;
var HDPrivateKey = keyLib.HDPrivateKey;
var HDPublicKey = keyLib.HDPublicKey;
var log = require('./common/log');
var Mnemonic = require('@owstack/mnemonic-lib');
var Package = require('../../package.json');
var PrivateKey = keyLib.PrivateKey;
var request = require('superagent');
var querystring = require('querystring');
var sjcl = require('sjcl');
var Signature = keyLib.crypto.Signature;
var url = require('url');
var util = require('util');
var lodash = owsCommon.deps.lodash;
var $ = require('preconditions').singleton();

var _deviceValidated;

/** 
 * Client Management
 * -----------------
 * [constructor] API(context, opts)
 * dispose(cb)
 * getVersion(cb)
 * initialize(opts, cb)
 * 
 * Wallet Seeding
 * --------------
 * seedFromExtendedPrivateKey(xPrivKey, opts)
 * seedFromExtendedPublicKey(xPubKey, source, entropySourceHex, opts)
 * seedFromMnemonic(words, opts)
 * seedFromRandom(opts)
 * seedFromRandomWithMnemonic(opts)
 * 
 * Wallet Management
 * -----------------
 * addAccess(opts, cb)
 * createWallet(walletName, copayerName, m, n, opts, cb)
 * getPreferences(cb)
 * openWallet(cb)
 * recreateWallet(cb)
 * savePreferences(preferences, cb)
 * _processWallet(wallet)
 * [static] _extractPublicKeyRing(copayers)
 * addWalletInfo(credentials, walletId, walletName, m, n, copayerName)
 * 
 * Shared Wallet
 * -------------
 * isComplete()
 * joinWallet(secret, copayerName, opts, cb)
 * parseSecret(secret)
 * _buildSecret(walletId, privKey, networkName)
 * _doJoinWallet(walletId, privKey, xPubKey, requestPubKey, copayerName, opts, cb)
 * 
 * Wallet Status
 * -------------
 * createAddress(opts, cb)
 * deriveAddress(scriptType, publicKeyRing, path, m, network)
 * getBalance(opts, cb)
 * getBalanceFromPrivateKey(privateKey, cb)
 * getMainAddresses(opts, cb)
 * getSendMaxInfo(opts, cb)
 * getStatus(opts, cb)
 * getStatusByIdentifier(opts, cb)
 * startScan(opts, cb)
 * _processStatus(status)
 * 
 * Wallet Keys
 * -----------
 * checkPassword(password)
 * encryptPrivateKey(password, opts)
 * decryptBIP38PrivateKey(encryptedPrivateKeyBase58, passphrase, opts, cb)
 * decryptPrivateKey(password)
 * getKeys(password)
 * getPrivKeyExternalSourceName()
 * isPrivKeyEncrypted()
 * isPrivKeyExternal()
 * validateKeyDerivation(opts, cb)
 * [static object] privateKeyEncryptionOpts
 * _checkKeyDerivation()
 * 
 * Wallet Mnemonics
 * ----------------
 * clearMnemonic()
 * getMnemonic()
 * mnemonicHasPassphrase()
 * 
 * Wallet Import/Export
 * --------------------
 * export(opts)
 * import(str)
 * importFromMnemonic(words, opts, cb)
 * importFromExtendedPrivateKey(xPrivKey, opts, cb)
 * importFromExtendedPublicKey(xPubKey, source, entropySourceHex, opts, cb)
 * _import(cb)
 * 
 * Transaction and Proposals
 * -------------------------
 * broadcastRawTx(opts, cb)
 * broadcastTxProposal(txp, cb)
 * buildTx(txp)
 * buildTxFromPrivateKey(privateKey, destinationAddress, opts, cb)
 * canSign()
 * createTxProposal(opts, cb)
 * editTxNote(opts, cb)
 * getRawTx(txp)
 * getTx(id, cb)
 * getTxHistory(opts, cb)
 * getTxNote(opts, cb)
 * getTxNotes(opts, cb)
 * getTxProposals(opts, cb)
 * getUtxos(opts, cb)
 * publishTxProposal(opts, cb)
 * rejectTxProposal(txp, reason, cb)
 * removeTxProposal(txp, cb)
 * signTxp(txp, derivedXPrivKey)
 * signTxProposal(txp, password, cb)
 * signTxProposalFromAirGapped(txp, encryptedPkr, m, n, password)
 * signTxProposalFromAirGappedWithNewClient(key, txp, unencryptedPkr, m, n, opts)
 * _addSignaturesToTx(txp, t, signatures, xpub)
 * _applyAllSignatures(txp, t)
 * _doBroadcast(txp, cb)
 * _getCreateTxProposalArgs(opts)
 * _getCurrentSignatures(txp)
 * _processTxNotes(notes)
 * _processTxps(txps)
 * _signTxp(txp, password)
 * 
 * Payment Prototcol
 * -----------------
 * fetchPayPro(opts, cb)
 * getPayPro(txp, cb)
 * 
 * Notifications
 * -------------
 * getNotifications(opts, cb)
 * pushNotificationsSubscribe(opts, cb)
 * pushNotificationsUnsubscribe(token, cb)
 * setNotificationsInterval(notificationIntervalSeconds)
 * txConfirmationSubscribe(opts, cb)
 * txConfirmationUnsubscribe(txid, cb)
 * _disposeNotifications()
 * _fetchLatestNotifications(interval, cb)
 * _initNotifications(opts)
 * 
 * Exchange Rates
 * --------------
 * getFeeLevels(networkName, cb)
 * getFiatRate(opts, cb)
 * 
 * Message Encryption
 * ------------------
 * _encryptMessage(message, encryptingKey)
 * _decryptMessage(message, encryptingKey)
 * 
 * Utilities
 * ---------
 * formatAmount(atomics, unit, opts)
 * 
 * HTTP Request Handling
 * ---------------------
 * _doDeleteRequest(url, cb)
 * _doRequest(method, url, args, useSession, cb)
 * _doRequestWithLogin(method, url, args, cb)
 * _doPostRequest(url, args, cb)
 * _doPutRequest(url, args, cb)
 * _doGetRequest(url, cb)
 * _doGetRequestWithLogin(url, cb)
 * _getHeaders(method, url, args)
 * _login(cb)
 * _logout(cb)
 * _signRequest(method, url, args, privKey)
 * [static] _parseError(body)
 */

/**************************************************
 *
 * Client Management
 *
 **************************************************/

/**
 * @desc ClientAPI constructor.
 *
 * @param {Object} opts
 * @constructor
 */
class API extends EventEmitter {
  constructor(context, opts) {
    super();

    // Context defines the coin network and is set by the implementing client in
    // order to instance this base client; e.g., btc-client.
    context.inject(this);

    // Set some frequently used contant values based on context.
    this.LIVENET = this.ctx.Networks.livenet;
    this.TESTNET = this.ctx.Networks.testnet;

    opts = opts || {};

    this.request = opts.request || request;
    this.baseUrl = opts.baseUrl || this.ctx.Defaults.BASE_URL;
    this.payProHttp = null; // Only for testing
    this.doNotVerifyPayPro = opts.doNotVerifyPayPro;
    this.timeout = opts.timeout || 50000;
    this.supportStaffWalletId = opts.supportStaffWalletId;

    this.paypro = new this.ctx.PayPro(opts);
    this.utils = new this.ctx.Utils();
    this.verifier = new this.ctx.Verifier(opts, this);

    // Expose some library classes.
    this.Address = this.ctx.Address;
    this.URI = this.ctx.URI;
    this.Unit = this.ctx.Unit;

    this.log = opts.log || log;
  }
};

API.prototype.dispose = function(cb) {
  var self = this;
  self._disposeNotifications();
  self._logout(cb);
};

/**
 * Get service version
 *
 * @param {Callback} cb
 */
API.prototype.getVersion = function(cb) {
  this._doGetRequest('/v1/version/', cb);
};

API.prototype.initialize = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }

  self.notificationIncludeOwn = !!opts.notificationIncludeOwn;
  self._initNotifications(opts);
  return cb();
};

/**************************************************
 *
 * Wallet Seeding
 *
 **************************************************/

/**
 * Seed from extended private key
 *
 * @param {String} xPrivKey
 * @param {Number} opts.account - default 0
 * @param {String} opts.derivationStrategy - default 'BIP44'
 */
API.prototype.seedFromExtendedPrivateKey = function(xPrivKey, opts) {
  var self = this;
  opts = opts || {};
  self.credentials = Credentials.fromExtendedPrivateKey(xPrivKey, opts.account || 0, opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44, opts);
};

/**
 * Seed from external wallet public key
 *
 * @param {String} xPubKey
 * @param {String} source - A name identifying the source of the xPrivKey (e.g. ledger, TREZOR, ...)
 * @param {String} entropySourceHex - A HEX string containing pseudo-random data, that can be deterministically derived from the xPrivKey, and should not be derived from xPubKey.
 * @param {Object} opts
 * @param {Number} opts.account - default 0
 * @param {String} opts.derivationStrategy - default 'BIP44'
 */
API.prototype.seedFromExtendedPublicKey = function(xPubKey, source, entropySourceHex, opts) {
  var self = this;
  $.checkArgument(lodash.isUndefined(opts) || lodash.isObject(opts));
  opts = opts || {};
  self.credentials = Credentials.fromExtendedPublicKey(xPubKey, source, entropySourceHex, opts);
};

/**
 * Seed from Mnemonics (language autodetected)
 * Can throw an error if mnemonic is invalid
 *
 * @param {String} BIP39 words
 * @param {Object} opts
 * @param {String} opts.networkName - default LIVENET.name
 * @param {String} opts.passphrase
 * @param {Number} opts.account - default 0
 * @param {String} opts.derivationStrategy - default 'BIP44'
 */
API.prototype.seedFromMnemonic = function(words, opts) {
  var self = this;
  $.checkArgument(lodash.isUndefined(opts) || lodash.isObject(opts), 'DEPRECATED: second argument should be an options object.');

  opts = opts || {};
  self.credentials = Credentials.fromMnemonic(words, {
    networkName: opts.networkName || self.LIVENET.name,
    passphrase: opts.passphrase,
    account: opts.account || 0,
    derivationStrategy: opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44,
    opts
  });
};

/**
 * Seed from random
 *
 * @param {Object} opts
 * @param {String} opts.networkName - default LIVENET.name
 */
API.prototype.seedFromRandom = function(opts) {
  var self = this;
  opts = opts || {};
  self.credentials = Credentials.fromRandom({
    networkName: opts.networkName || self.LIVENET.name
  });
};

/**
 * Seed from random with mnemonic
 *
 * @param {Object} opts
 * @param {String} opts.networkName - default LIVENET.name
 * @param {String} opts.passphrase
 * @param {Number} opts.language - default 'en'
 * @param {Number} opts.account - default 0
 */
API.prototype.seedFromRandomWithMnemonic = function(opts) {
  var self = this;
  opts = opts || {};
  opts.networkName = opts.networkName || self.LIVENET.name;
  opts.langauge = opts.language || 'en';
  opts.account = opts.account || 0;

  self.credentials = Credentials.fromRandomMnemonic(opts);
};

/**************************************************
 *
 * Wallet Management
 *
 **************************************************/

/**
 * Adds access to the current copayer
 * @param {Object} opts
 * @param {bool} opts.generateNewKey Optional: generate a new key for the new access
 * @param {string} opts.restrictions
 *    - cannotProposeTXs
 *    - cannotXXX TODO
 * @param {string} opts.name  (name for the new access)
 *
 * return the accesses Wallet and the requestPrivateKey
 */
API.prototype.addAccess = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials && self.credentials.canSign());
  } catch (e) {
    return cb(e);
  }

  opts = opts || {};

  var reqPrivKey = new PrivateKey(opts.generateNewKey ? null : self.credentials.requestPrivKey);
  var requestPubKey = reqPrivKey.toPublicKey().toString();

  var xPriv = new HDPrivateKey(self.credentials.xPrivKey).deriveChild(self.credentials.getBaseAddressDerivationPath());
  var sig = self.ctx.Utils.signRequestPubKey(requestPubKey, xPriv);
  var copayerId = self.credentials.copayerId;

  var encCopayerName = opts.name ? self.ctx.Utils.encryptMessage(opts.name, self.credentials.sharedEncryptingKey) : null;

  var opts = {
    copayerId: copayerId,
    requestPubKey: requestPubKey,
    signature: sig,
    name: encCopayerName,
    restrictions: opts.restrictions,
  };

  self._doPutRequest('/v1/copayers/' + copayerId + '/', opts, function(err, res) {
    if (err) {
      return cb(err);
    }
    return cb(null, res.wallet, reqPrivKey);
  });
};

/**
 *
 * Create a wallet.
 * @param {String} walletName
 * @param {String} copayerName
 * @param {Number} m
 * @param {Number} n
 * @param {object} opts (optional: advanced options)
 * @param {string} opts.networkName[=LIVENET.name]
 * @param {string} opts.singleAddress[=false] - The wallet will only ever have one address.
 * @param {String} opts.privKey - set a privKey (instead of random)
 * @param {String} opts.id - set a id for wallet (instead of server given)
 * @param cb
 * @return {undefined}
 */
API.prototype.createWallet = function(walletName, copayerName, m, n, opts, cb) {
  var self = this;

  if (!self._checkKeyDerivation()) {
    return cb(new Error('Cannot create new wallet'));
  }

  if (opts) {
    $.shouldBeObject(opts);
  }
  opts = opts || {};

  var networkName = opts.networkName || self.LIVENET.name;

  if (!lodash.includes([self.LIVENET.name, self.TESTNET.name], networkName)) {
    return cb(new Error('Invalid network'));
  }

  if (!self.credentials) {
    self.log.info('Generating new keys for ' + networkName);
    self.seedFromRandom({
      networkName: networkName
    });
  } else {
    self.log.info('Using existing keys');
  }

  if (networkName != self.credentials.networkName) {
    return cb(new Error('Existing keys were created for a different network'));
  }

  var privKey = opts.privKey || new PrivateKey();

  var c = self.credentials;
  c.addPrivateKey(privKey.toString());
  var encWalletName = self.ctx.Utils.encryptMessage(walletName, c.sharedEncryptingKey);

  var args = {
    name: encWalletName,
    m: m,
    n: n,
    pubKey: (new PrivateKey(privKey)).toPublicKey().toString(),
    networkName: networkName,
    singleAddress: !!opts.singleAddress,
    id: opts.id,
  };

  self._doPostRequest('/v1/wallets/', args, function(err, res) {
    if (err) {
      return cb(err);
    }

    var walletId = res.walletId;

    addWalletInfo(c, walletId, walletName, m, n, copayerName);
    var secret = self._buildSecret(c.walletId, c.privKey, c.networkName);

    self._doJoinWallet(walletId, privKey, c.xPubKey, c.requestPubKey, copayerName, {},
      function(err, wallet) {
        if (err) {
          return cb(err);
        }
        return cb(null, n > 1 ? secret : null);
      });
  });
};

/**
 * Get copayer preferences
 *
 * @param {Callback} cb
 * @return {Callback} cb - Return error or object
 */
API.prototype.getPreferences = function(cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }

  $.checkArgument(cb);

  self._doGetRequest('/v1/preferences/', function(err, preferences) {
    if (err) {
      return cb(err);
    }
    return cb(null, preferences);
  });
};

/**
 * Open a wallet and try to complete the public key ring.
 *
 * @param {Callback} cb - The callback that handles the response. It returns a flag indicating that the wallet is complete.
 * @fires API#walletCompleted
 */
API.prototype.openWallet = function(cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }

  if (self.isComplete() && self.hasWalletInfo()) {
    return cb(null, true);
  }

  self._doGetRequest('/v1/wallets/?includeExtendedInfo=1', function(err, ret) {
    if (err) {
      return cb(err);
    }

    var wallet = ret.wallet;

    self._processStatus(ret);

    if (!self.hasWalletInfo()) {
      var me = lodash.find(wallet.copayers, {
        id: self.credentials.copayerId
      });
      addWalletInfo(self.credentials, wallet.id, wallet.name, wallet.m, wallet.n, me.name);
    }

    if (wallet.status != 'complete') {
      return cb();
    }

    if (self.credentials.privKey) {
      if (!self.verifier.checkCopayers(self.credentials, wallet.copayers)) {
        return cb(new Errors.SERVER_COMPROMISED);
      }
    } else {
      // this should only happen in AIR-GAPPED flows
      self.log.warn('Could not verify copayers key (missing wallet Private Key)');
    }

    self.credentials.addPublicKeyRing(API._extractPublicKeyRing(wallet.copayers));

    self.emit('walletCompleted', wallet);

    return cb(null, ret);
  });
};

/**
 * Recreates a wallet, given credentials (with wallet id)
 *
 * @returns {Callback} cb - Returns the wallet
 */
API.prototype.recreateWallet = function(cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
    $.checkState(self.credentials.privKey);
    $.checkState(self.isComplete());
    //$.checkState(self.credentials.hasWalletInfo();
  } catch (e) {
    return cb(e);
  }

  // First: Try to get the wallet with current credentials
  self.getStatus({
    includeExtendedInfo: true
  }, function(err) {
    // No error? -> Wallet is ready.
    if (!err) {
      self.log.info('Wallet is already created');
      return cb();
    };

    var c = self.credentials;
    var privKey = PrivateKey.fromString(c.privKey);
    var walletId = c.walletId;
    var supportBIP44AndP2PKH = c.derivationStrategy != Constants.DERIVATION_STRATEGIES.BIP45;
    var encWalletName = self.ctx.Utils.encryptMessage(c.walletName || 'recovered wallet', c.sharedEncryptingKey);

    var args = {
      name: encWalletName,
      m: c.m,
      n: c.n,
      pubKey: privKey.toPublicKey().toString(),
      networkName: c.networkName,
      id: walletId,
      supportBIP44AndP2PKH: supportBIP44AndP2PKH,
    };

    self._doPostRequest('/v1/wallets/', args, function(err, body) {
      if (err) {
        if (!(err instanceof Errors.WALLET_ALREADY_EXISTS)) {
          return cb(err);
        }

        return self.addAccess({}, function(err) {
          if (err) {
            return cb(err);
          }
          self.openWallet(function(err) {
            return cb(err);
          });
        });
      }

      if (!walletId) {
        walletId = body.walletId;
      }

      var i = 1;
      async.each(self.credentials.publicKeyRing, function(item, next) {
        var name = item.copayerName || ('copayer ' + i++);
        self._doJoinWallet(walletId, privKey, item.xPubKey, item.requestPubKey || item.requestPubKeys[0].key, name, {
          supportBIP44AndP2PKH: supportBIP44AndP2PKH,
        }, function(err) {
          //Ignore error is copayer already in wallet
          if (err && err instanceof Errors.COPAYER_IN_WALLET) {
            return next();
          }
          return next(err);
        });
      }, cb);
    });
  });
};

/**
 * Save copayer preferences
 *
 * @param {Object} preferences
 * @param {Callback} cb
 * @return {Callback} cb - Return error or object
 */
API.prototype.savePreferences = function(preferences, cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }
  $.checkArgument(cb);

  self._doPutRequest('/v1/preferences/', preferences, cb);
};

API.prototype._processWallet = function(wallet) {
  var self = this;
  var encryptingKey = self.credentials.sharedEncryptingKey;
  var name = self.ctx.Utils.decryptMessage(wallet.name, encryptingKey);

  if (name != wallet.name) {
    wallet.encryptedName = wallet.name;
  }

  wallet.name = name;

  lodash.each(wallet.copayers, function(copayer) {
    var name = self.ctx.Utils.decryptMessage(copayer.name, encryptingKey);

    if (name != copayer.name) {
      copayer.encryptedName = copayer.name;
    }

    copayer.name = name;

    lodash.each(copayer.requestPubKeys, function(access) {
      if (!access.name) {
        return;
      }

      var name = self.ctx.Utils.decryptMessage(access.name, encryptingKey);
      if (name != access.name) {
        access.encryptedName = access.name;
      }

      access.name = name;
    });
  });
};

API._extractPublicKeyRing = function(copayers) {
  return lodash.map(copayers, function(copayer) {
    var pkr = lodash.pick(copayer, ['xPubKey', 'requestPubKeys']);
    pkr.copayerName = copayer.name;
    return pkr;
  });
};

function addWalletInfo(credentials, walletId, walletName, m, n, copayerName) {
  var info = {
    type: 'wallet',
    walletId: walletId,
    walletName: walletName,
    m: m,
    n: n
  };

  if (copayerName) {
    info.copayerName = copayerName;
  }

  if (credentials.derivationStrategy == 'BIP44' && n == 1) {
    info.addressType = Constants.SCRIPT_TYPES.P2PKH;
  } else {
    info.addressType = Constants.SCRIPT_TYPES.P2SH;
  }

  // Use m/48' for multisig hardware wallets
  if (!credentials.xPrivKey && credentials.externalSource && n > 1) {
    info.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP48;
  }

  if (n == 1) {
    credentials.addPublicKeyRing([{
      xPubKey: credentials.xPubKey,
      requestPubKey: credentials.requestPubKey,
    }]);
  }

  credentials.extend(info);
};

/**************************************************
 *
 * Shared Wallet
 *
 **************************************************/

/**
 * Return true if wallet is complete
 */
API.prototype.isComplete = function() {
  var c = this.credentials;
  if (c && (!c.m || !c.n || !c.publicKeyRing || c.publicKeyRing.length != c.n)) {
    return false;
  }
  return true;    
};

/**
 * Return true if credentials is a wallet
 */
API.prototype.hasWalletInfo = function() {
  return !!this.credentials.walletId;
};

/**
 * Join an existent wallet
 *
 * @param {String} secret
 * @param {String} copayerName
 * @param {Object} opts
 * @param {Boolean} opts.dryRun[=false] - Simulate wallet join
 * @param {Callback} cb
 * @returns {Callback} cb - Returns the wallet
 */
API.prototype.joinWallet = function(secret, copayerName, opts, cb) {
  var self = this;

  if (!self._checkKeyDerivation()) {
    return cb(new Error('Cannot join wallet'));
  }

  opts = opts || {};

  try {
    var secretData = self.parseSecret(secret);
  } catch (ex) {
    return cb(ex);
  }

  if (!self.credentials) {
    self.seedFromRandom({
      networkName: secretData.networkName
    });
  }

  self.credentials.addPrivateKey(secretData.privKey.toString());
  self._doJoinWallet(secretData.walletId, secretData.privKey, self.credentials.xPubKey, self.credentials.requestPubKey, copayerName, {
    dryRun: !!opts.dryRun,
  }, function(err, wallet) {
    if (err) {
      return cb(err);
    }
    if (!opts.dryRun) {
      addWalletInfo(self.credentials, wallet.id, wallet.name, wallet.m, wallet.n, copayerName);
    }
    return cb(null, wallet);
  });
};

API.prototype.parseSecret = function(secret) {
  var self = this;
  $.checkArgument(secret);

  function split(str, indexes) {
    var parts = [];
    indexes.push(str.length);
    var i = 0;
    while (i < indexes.length) {
      parts.push(str.substring(i == 0 ? 0 : indexes[i - 1], indexes[i]));
      i++;
    };
    return parts;
  };

  try {
    var secretSplit = split(secret, [22, 74]);
    var widBase58 = secretSplit[0].replace(/0/g, '');
    var widHex = Base58.decode(widBase58).toString('hex');
    var walletId = split(widHex, [8, 12, 16, 20]).join('-');
    var networkNameBase58 = secretSplit[2];
    var networkName = Base58.decode(networkNameBase58).toString('ascii');
    var privKey = PrivateKey.fromString(secretSplit[1], networkName);

    if (!lodash.includes([self.LIVENET.name, self.TESTNET.name], networkName)) {
      // Secret is not for this network
      throw false;
    }

    return {
      walletId: walletId,
      privKey: privKey,
      networkName: networkName
    };
  } catch (ex) {
    throw new Error('Invalid secret');
  }
};

API.prototype._buildSecret = function(walletId, privKey, networkName) {
  var self = this;
  if (lodash.isString(privKey)) {
    privKey = PrivateKey.fromString(privKey, networkName);
  }

  var widHex = new Buffer(walletId.replace(/-/g, ''), 'hex');
  var widBase58 = new Base58(widHex).toString();
  var networkNameHex = new Buffer(networkName, 'ascii');
  var networkNameBase58 = new Base58(networkNameHex).toString();

  return lodash.padEnd(widBase58, 22, '0') + privKey.toWIF() + networkNameBase58;
};

/**
 * Join
 * @private
 *
 * @param {String} walletId
 * @param {String} privKey
 * @param {String} xPubKey
 * @param {String} requestPubKey
 * @param {String} copayerName
 * @param {Object} Optional args
 * @param {String} opts.customData
 * @param {Callback} cb
 */
API.prototype._doJoinWallet = function(walletId, privKey, xPubKey, requestPubKey, copayerName, opts, cb) {
  var self = this;
  $.shouldBeFunction(cb);

  opts = opts || {};

  // Adds encrypted walletPrivateKey to CustomData
  opts.customData = opts.customData || {};
  opts.customData.privKey = privKey.toString();
  var encCustomData = self.ctx.Utils.encryptMessage(JSON.stringify(opts.customData), self.credentials.personalEncryptingKey);
  var encCopayerName = self.ctx.Utils.encryptMessage(copayerName, self.credentials.sharedEncryptingKey);

  var args = {
    walletId: walletId,
    name: encCopayerName,
    xPubKey: xPubKey,
    requestPubKey: requestPubKey,
    customData: encCustomData,
  };

  if (opts.dryRun) {
    args.dryRun = true;
  }

  if (lodash.isBoolean(opts.supportBIP44AndP2PKH)) {
    args.supportBIP44AndP2PKH = opts.supportBIP44AndP2PKH;
  }

  var hash = self.ctx.Utils.getCopayerHash(args.name, args.xPubKey, args.requestPubKey);
  args.copayerSignature = self.ctx.Utils.signMessage(hash, privKey);

  var url = '/v1/wallets/' + walletId + '/copayers';

  self._doPostRequest(url, args, function(err, body) {
    if (err) {
      return cb(err);
    }
    self._processWallet(body.wallet);
    return cb(null, body.wallet);
  });
};

/**************************************************
 *
 * Wallet Status
 *
 **************************************************/

/**
 * Create a new address
 *
 * @param {Object} opts
 * @param {Boolean} opts.ignoreMaxGap[=false]
 * @param {Callback} cb
 * @returns {Callback} cb - Return error or the address
 */
API.prototype.createAddress = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials && self.isComplete());
  } catch (e) {
    return cb(e);
  }

  if (!self._checkKeyDerivation()) {
    return cb(new Error('Cannot create new address for this wallet'));
  }

  opts = opts || {};

  self._doPostRequest('/v1/addresses/', opts, function(err, address) {
    if (err) {
      return cb(err);
    }

    if (!self.verifier.checkAddress(address)) {
      return cb(new Errors.SERVER_COMPROMISED);
    }

    return cb(null, address);
  });
};

API.prototype.deriveAddress = function(scriptType, publicKeyRing, path, m, network) {
  var self = this;
  $.checkArgument(lodash.includes(lodash.values(Constants.SCRIPT_TYPES), scriptType));

  var publicKeys = lodash.map(publicKeyRing, function(item) {
    var xpub = new HDPublicKey(item.xPubKey);
    return xpub.deriveChild(path).publicKey;
  });

  var address;
  switch (scriptType) {
    case Constants.SCRIPT_TYPES.P2SH:
      address = self.ctx.Address.createMultisig(publicKeys, m, network);
      break;
    case Constants.SCRIPT_TYPES.P2PKH:
      $.checkState(lodash.isArray(publicKeys) && publicKeys.length == 1);
      address = self.ctx.Address.fromPublicKey(publicKeys[0], network);
      break;
  }

  return {
    address: address.toString(),
    path: path,
    publicKeys: lodash.invokeMap(publicKeys, 'toString'),
  };
};

/**
 * Update wallet balance
 *
 * @param {Boolean} opts.twoStep[=false] - Optional: use 2-step balance computation for improved performance
 * @param {Callback} cb
 */
API.prototype.getBalance = function(opts, cb) {
  var self = this;

  opts = opts || {};

  try{
    $.checkState(self.credentials && self.isComplete());
  } catch (e) {
    return cb(e);
  }

  var url = '/v1/balance/';
  if (opts.twoStep) {
    url += '?twoStep=1';
  }

  self._doGetRequest(url, cb);
};

API.prototype.getBalanceFromPrivateKey = function(privateKey, cb) {
  var self = this;
  var privateKey = new PrivateKey(privateKey);
  var address = self.ctx.Address.fromPublicKey(privateKey.publicKey);

  self.getUtxos({
    addresses: address.toString(),
  }, function(err, utxos) {
    if (err) {
      return cb(err);
    }
    return cb(null, lodash.sumBy(utxos, self.Unit().atomicsAccessor()), address.toString());
  });
};

/**
 * Get your main addresses
 *
 * @param {Object} opts
 * @param {Boolean} opts.doNotVerify
 * @param {Numeric} opts.limit (optional) - Limit the resultset. Return all addresses by default.
 * @param {Boolean} [opts.reverse=false] (optional) - Reverse the order of returned addresses.
 * @param {Callback} cb
 * @returns {Callback} cb - Return error or the array of addresses
 */
API.prototype.getMainAddresses = function(opts, cb) {
  var self = this;
  try {
    $.checkState(self.credentials && self.isComplete());
  } catch (e) {
    return cb(e);
  }

  opts = opts || {};
  var args = [];

  if (opts.limit) {
    args.push('limit=' + opts.limit);
  }

  if (opts.reverse) {
    args.push('reverse=1');
  }

  var qs = '';
  if (args.length > 0) {
    qs = '?' + args.join('&');
  }
  var url = '/v1/addresses/' + qs;

  self._doGetRequest(url, function(err, addresses) {
    if (err) {
      return cb(err);
    }

    if (!opts.doNotVerify) {
      var fake = lodash.some(addresses, function(address) {
        return !self.verifier.checkAddress(address);
      });
      if (fake) {
        return cb(new Errors.SERVER_COMPROMISED);
      }
    }
    return cb(null, addresses);
  });
};

/**
 * Returns send max information.
 * @param {String} opts
 * @param {number} opts.feeLevel[='normal'] - Optional. Specify the fee level ('priority', 'normal', 'economy', 'superEconomy').
 * @param {number} opts.feePerKb - Optional. Specify the fee per KB (in atomic unit).
 * @param {Boolean} opts.excludeUnconfirmedUtxos - Indicates it if should use (or not) the unconfirmed utxos
 * @param {Boolean} opts.returnInputs - Indicates it if should return (or not) the inputs
 * @return {Callback} cb - Return error (if exists) and object result
 */
API.prototype.getSendMaxInfo = function(opts, cb) {
  var self = this;
  var args = [];
  opts = opts || {};

  if (opts.feeLevel) {
    args.push('feeLevel=' + opts.feeLevel);
  }

  if (opts.feePerKb) {
    args.push('feePerKb=' + opts.feePerKb);
  }

  if (opts.excludeUnconfirmedUtxos) {
    args.push('excludeUnconfirmedUtxos=1');
  }

  if (opts.returnInputs) {
    args.push('returnInputs=1');
  }

  var qs = '';

  if (args.length > 0) {
    qs = '?' + args.join('&');
  }

  var url = '/v1/sendmaxinfo/' + qs;

  self._doGetRequest(url, function(err, result) {
    if (err) {
      return cb(err);
    }
    return cb(null, result);
  });
};

/**
 * Get status of the wallet
 *
 * @param {Boolean} opts.twoStep[=false] - Optional: use 2-step balance computation for improved performance
 * @param {Boolean} opts.includeExtendedInfo (optional: query extended status)
 * @returns {Callback} cb - Returns error or an object with status information
 */
API.prototype.getStatus = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }

  opts = opts || {};

  var qs = [];
  qs.push('includeExtendedInfo=' + (opts.includeExtendedInfo ? '1' : '0'));
  qs.push('twoStep=' + (opts.twoStep ? '1' : '0'));

  self._doGetRequest('/v1/wallets/?' + qs.join('&'), function(err, result) {
    if (err) {
      return cb(err);
    }
    if (result.wallet.status == 'pending') {
      var c = self.credentials;
      result.wallet.secret = self._buildSecret(c.walletId, c.privKey, c.networkName);
    }

    self._processStatus(result);

    return cb(err, result);
  });
};

/**
 * Get wallet status based on a string identifier (one of: walletId, address, txid)
 *
 * @param {string} opts.identifier - The identifier
 * @param {Boolean} opts.twoStep[=false] - Optional: use 2-step balance computation for improved performance
 * @param {Boolean} opts.includeExtendedInfo (optional: query extended status)
 * @returns {Callback} cb - Returns error or an object with status information
 */
API.prototype.getStatusByIdentifier = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }

  opts = opts || {};

  var qs = [];
  qs.push('includeExtendedInfo=' + (opts.includeExtendedInfo ? '1' : '0'));
  qs.push('twoStep=' + (opts.twoStep ? '1' : '0'));

  self._doGetRequest('/v1/wallets/' + opts.identifier + '?' + qs.join('&'), function(err, result) {
    if (err || !result || !result.wallet) {
      return cb(err);
    }
    if (result.wallet.status == 'pending') {
      var c = self.credentials;
      result.wallet.secret = self._buildSecret(c.walletId, c.privKey, c.networkName);
    }

    self._processStatus(result);

    return cb(err, result);
  });
};

/**
 * Start an address scanning process.
 * When finished, the scanning process will send a notification 'ScanFinished' to all copayers.
 *
 * @param {Object} opts
 * @param {Boolean} opts.includeCopayerBranches (defaults to false)
 * @param {Callback} cb
 */
API.prototype.startScan = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials && self.isComplete());
  } catch (e) {
    return cb(e);
  }

  var args = {
    includeCopayerBranches: opts.includeCopayerBranches,
  };

  self._doPostRequest('/v1/addresses/scan', args, function(err) {
    return cb(err);
  });
};

API.prototype._processStatus = function(status) {
  var self = this;

  function processCustomData(data) {
    var copayers = data.wallet.copayers;
    if (!copayers) {
      return;
    }

    var me = lodash.find(copayers, {
      'id': self.credentials.copayerId
    });
    if (!me || !me.customData) {
      return;
    }

    var customData;

    try {
      customData = JSON.parse(self.ctx.Utils.decryptMessage(me.customData, self.credentials.personalEncryptingKey));
    } catch (e) {
      self.log.warn('Could not decrypt customData:', me.customData);
    }

    if (!customData) {
      return;
    }

    // Add it to result
    data.customData = customData;

    // Update walletPrivateKey
    if (!self.credentials.privKey && customData.privKey) {
      self.credentials.addPrivateKey(customData.privKey);
    }
  };

  processCustomData(status);
  self._processWallet(status.wallet);
  self._processTxps(status.pendingTxps);
};

/**************************************************
 *
 * Wallet Keys
 *
 **************************************************/

/**
 * Checks is password is valid
 * Returns null (keys not encrypted), true or false.
 *
 * @param password
 */
API.prototype.checkPassword = function(password) {
  var self = this;
  if (!self.isPrivKeyEncrypted()) {
    return;
  }

  try {
    var keys = self.getKeys(password);
    return !!keys.xPrivKey;
  } catch (e) {
    return false;
  };
};

/**
 * sets up encryption for the extended private key
 *
 * @param {String} password Password used to encrypt
 * @param {Object} opts optional: SJCL options to encrypt (.iter, .salt, etc).
 * @return {undefined}
 */
API.prototype.encryptPrivateKey = function(password, opts) {
  this.credentials.encryptPrivateKey(password, opts || API.privateKeyEncryptionOpts);
};

API.prototype.decryptBIP38PrivateKey = function(encryptedPrivateKeyBase58, passphrase, opts, cb) {
  var self = this;
  var bip38 = new Bip38();

  var privateKeyWif;
  try {
    privateKeyWif = bip38.decrypt(encryptedPrivateKeyBase58, passphrase);
  } catch (ex) {
    return cb(new Error('Could not decrypt BIP38 private key', ex));
  }

  var privateKey = new PrivateKey(privateKeyWif);
  var address = self.ctx.Address(privateKey.publicKey).toString();
  var addrBuff = new Buffer(address, 'ascii');
  var actualChecksum = Hash.sha256sha256(addrBuff).toString('hex').substring(0, 8);
  var expectedChecksum = Base58Check.decode(encryptedPrivateKeyBase58).toString('hex').substring(6, 14);

  if (actualChecksum != expectedChecksum)
    return cb(new Error('Incorrect passphrase'));

  return cb(null, privateKeyWif);
};

/**
 * disables encryption for private key.
 *
 * @param {String} password Password used to encrypt
 */
API.prototype.decryptPrivateKey = function(password) {
  return this.credentials.decryptPrivateKey(password);
};

/**
 * Returns unencrypted extended private key and mnemonics
 *
 * @param password
 */
API.prototype.getKeys = function(password) {
  return this.credentials.getKeys(password);
};

/**
 * Get external wallet source name
 *
 * @return {String}
 */
API.prototype.getPrivKeyExternalSourceName = function() {
  return this.credentials ? this.credentials.getExternalSourceName() : null;
};

/**
 * Is private key currently encrypted?
 *
 * @return {Boolean}
 */
API.prototype.isPrivKeyEncrypted = function() {
  return this.credentials && this.credentials.isPrivKeyEncrypted();
};

/**
 * Is private key external?
 *
 * @return {Boolean}
 */
API.prototype.isPrivKeyExternal = function() {
  return this.credentials && this.credentials.isPrivKeyExternal();
};

/**
 * Validate key derivation
 *
 * @param {Object} opts
 * @param {String} opts.passphrase
 * @param {String} opts.skipDeviceValidation
 */
API.prototype.validateKeyDerivation = function(opts, cb) {
  var self = this;
  opts = opts || {};
  var c = self.credentials;

  function testMessageSigning(xpriv, xpub) {
    var nonHardenedPath = 'm/0/0';
    var message = 'Lorem ipsum dolor sit amet, ne amet urbanitas percipitur vim, libris disputando his ne, et facer suavitate qui. Ei quidam laoreet sea. Cu pro dico aliquip gubergren, in mundi postea usu. Ad labitur posidonium interesset duo, est et doctus molestie adipiscing.';
    var priv = xpriv.deriveChild(nonHardenedPath).privateKey;
    var signature = self.ctx.Utils.signMessage(message, priv);
    var pub = xpub.deriveChild(nonHardenedPath).publicKey;
    return self.ctx.Utils.verifyMessage(message, signature, pub);
  };

  function testHardcodedKeys() {
    var words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    var xpriv = Mnemonic(words).toHDPrivateKey(null, 'btc');
    if (xpriv.toString() != 'xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu') {
      return false;
    }

    xpriv = xpriv.deriveChild("m/44'/0'/0'");
    if (xpriv.toString() != 'xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb') {
      return false;
    }

    var xpub = HDPublicKey.fromString('xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj');
    return testMessageSigning(xpriv, xpub);
  };

  function testLiveKeys() {
    var words;
    try {
      words = c.getMnemonic();
    } catch (ex) {}

    var xpriv;
    if (words && (!c.mnemonicHasPassphrase || opts.passphrase)) {
      var m = new Mnemonic(words);
      xpriv = m.toHDPrivateKey(opts.passphrase, c.networkName);
    }

    if (!xpriv) {
      xpriv = new HDPrivateKey(c.xPrivKey);
    }

    xpriv = xpriv.deriveChild(c.getBaseAddressDerivationPath());
    var xpub = new HDPublicKey(c.xPubKey);

    return testMessageSigning(xpriv, xpub);
  };

  var hardcodedOk = true;
  if (!_deviceValidated && !opts.skipDeviceValidation) {
    hardcodedOk = testHardcodedKeys();
    _deviceValidated = true;
  }

  var liveOk = (c.canSign() && !c.isPrivKeyEncrypted()) ? testLiveKeys() : true;
  self.keyDerivationOk = hardcodedOk && liveOk;

  return cb(null, self.keyDerivationOk);
};

API.privateKeyEncryptionOpts = {
  iter: 10000
};

API.prototype._checkKeyDerivation = function() {
  var self = this;
  var isInvalid = (self.keyDerivationOk === false);
  if (isInvalid) {
    self.log.error('Key derivation for this device is not working as expected');
  }
  return !isInvalid;
};

/**************************************************
 *
 * Wallet Mnemonics
 *
 **************************************************/

API.prototype.clearMnemonic = function() {
  return this.credentials.clearMnemonic();
};

API.prototype.getMnemonic = function() {
  return this.credentials.getMnemonic();
};

API.prototype.mnemonicHasPassphrase = function() {
  return this.credentials.mnemonicHasPassphrase;
};

/**************************************************
 *
 * Wallet Import/Export
 *
 **************************************************/

/**
 * Export wallet
 *
 * @param {Object} opts
 * @param {Boolean} opts.password
 * @param {Boolean} opts.noSign
 */
API.prototype.export = function(opts) {
  var self = this;
  $.checkState(self.credentials);

  opts = opts || {};
  var output;
  var c = Credentials.fromObj(self.credentials);

  if (opts.noSign) {
    c.setNoSign();
  } else if (opts.password) {
    c.decryptPrivateKey(opts.password);
  }

  output = JSON.stringify(c.toObj());

  return output;
};

/**
 * Import wallet
 *
 * @param {Object} str - The serialized JSON created with #export
 */
API.prototype.import = function(str) {
  var self = this;
  try {
    self.credentials = Credentials.fromObj(JSON.parse(str));
  } catch (ex) {
    throw new Errors.INVALID_BACKUP;
  }
};

/**
 * Import from Mnemonics (language autodetected)
 * Can throw an error if mnemonic is invalid
 *
 * @param {String} BIP39 words
 * @param {Object} opts
 * @param {String} opts.networkName - default LIVENET.name
 * @param {String} opts.passphrase
 * @param {Number} opts.account - default 0
 * @param {String} opts.derivationStrategy - default 'BIP44'
 * @param {String} opts.entropySourcePath - Only used if the wallet was created on a HW wallet, in which that private keys was not available for all the needed derivations
 * @param {String} opts.privKey - if available, privKey for encrypting metadata
 */
API.prototype.importFromMnemonic = function(words, opts, cb) {
  var self = this;
  self.log.debug('Importing from 12 Words');

  opts = opts || {};

  function derive() {
    return Credentials.fromMnemonic(words, {
      networkName: opts.networkName || self.LIVENET.name,
      passphrase: opts.passphrase,
      account: opts.account || 0,
      derivationStrategy: opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44,
      entropySourcePath: opts.entropySourcePath,
      privKey: opts.privKey
    });
  };

  try {
    self.credentials = derive();
  } catch (e) {
    self.log.info('Mnemonic error:', e);
    return cb(new Errors.INVALID_BACKUP);
  }

  self._import(function(err, ret) {
    if (!err) {
      return cb(null, ret);
    }
    if (err instanceof Errors.INVALID_BACKUP) {
      return cb(err);
    }
    if (err instanceof Errors.UNAUTHORIZED || err instanceof Errors.WALLET_DOES_NOT_EXIST) {
      var altCredentials = derive(true);
      if (altCredentials.xPubKey.toString() == self.credentials.xPubKey.toString()) {
        return cb(err);
      }
      self.credentials = altCredentials;
      return self._import(cb);
    }
    return cb(err);
  });
};

/*
 * Import from extended private key
 *
 * @param {String} xPrivKey
 * @param {Number} opts.account - default 0
 * @param {String} opts.derivationStrategy - default 'BIP44'
 * @param {String} opts.compliantDerivation - default 'true'
 * @param {String} opts.privKey - if available, privKey for encrypting metadata
 * @param {Callback} cb - The callback that handles the response. It returns a flag indicating that the wallet is imported.
 */
API.prototype.importFromExtendedPrivateKey = function(xPrivKey, opts, cb) {
  var self = this;
  self.log.debug('Importing from Extended Private Key');

  try {
    self.credentials = Credentials.fromExtendedPrivateKey(xPrivKey, opts.account || 0, opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44, opts);
  } catch (e) {
    self.log.info('xPriv error:', e);
    return cb(new Errors.INVALID_BACKUP);
  };

  self._import(cb);
};

/**
 * Import from Extended Public Key
 *
 * @param {String} xPubKey
 * @param {String} source - A name identifying the source of the xPrivKey
 * @param {String} entropySourceHex - A HEX string containing pseudo-random data, that can be deterministically derived from the xPrivKey, and should not be derived from xPubKey.
 * @param {Object} opts
 * @param {Number} opts.account - default 0
 * @param {String} opts.derivationStrategy - default 'BIP44'
 */
API.prototype.importFromExtendedPublicKey = function(xPubKey, source, entropySourceHex, opts, cb) {
  var self = this;
  $.checkArgument(arguments.length == 5, "DEPRECATED: should receive 5 arguments");
  $.checkArgument(lodash.isUndefined(opts) || lodash.isObject(opts));
  $.shouldBeFunction(cb);

  opts = opts || {};
  self.log.debug('Importing from Extended Private Key');
  try {
    self.credentials = Credentials.fromExtendedPublicKey(xPubKey, source, entropySourceHex, opts.account || 0, opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44);
  } catch (e) {
    self.log.info('xPriv error:', e);
    return cb(new Errors.INVALID_BACKUP);
  };

  self._import(cb);
};

API.prototype._import = function(cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }

  // First option, grab wallet info from wallet service.
  self.openWallet(function(err, ret) {

    // it worked?
    if (!err) {
      return cb(null, ret);
    }

    // Is the error other than "copayer was not found"? || or no priv key.
    if (err instanceof Errors.UNAUTHORIZED || self.isPrivKeyExternal()) {
      return cb(err);
    }

    //Second option, lets try to add an access
    self.log.info('Copayer not found, trying to add access');
    self.addAccess({}, function(err) {
      if (err) {
        return cb(new Errors.WALLET_DOES_NOT_EXIST);
      }

      self.openWallet(cb);
    });
  });
};

/**************************************************
 *
 * Transactions and Proposals
 *
 **************************************************/

/**
 * Broadcast raw transaction
 *
 * @param {Object} opts
 * @param {String} opts.rawTx
 * @param {Callback} cb
 * @return {Callback} cb - Return error or txid
 */
API.prototype.broadcastRawTx = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }

  $.checkArgument(cb);

  opts = opts || {};
  var url = '/v1/broadcast_raw/';
  
  self._doPostRequest(url, opts, function(err, txid) {
    if (err) {
      return cb(err);
    }
    return cb(null, txid);
  });
};

/**
 * Broadcast a transaction proposal
 *
 * @param {Object} txp
 * @param {Callback} cb
 * @return {Callback} cb - Return error or object
 */
API.prototype.broadcastTxProposal = function(txp, cb) {
  var self = this;
  try{
    $.checkState(self.credentials && self.isComplete());
  } catch (e) {
    return cb(e);
  }

  self.getPayPro(txp, function(err, paypro) {
    if (paypro) {
      var t = self.buildTx(txp);
      self._applyAllSignatures(txp, t);

      self.paypro.send({
        http: self.payProHttp,
        url: txp.payProUrl,
        amountSat: txp.amount,
        refundAddr: txp.changeAddress.address,
        merchant_data: paypro.merchant_data,
        rawTx: t.serialize({
          disableSmallFees: true,
          disableLargeFees: true,
          disableDustOutputs: true
        }),
      }, function(err, ack, memo) {
        if (err) {
          return cb(err);
        }
        self._doBroadcast(txp, function(err, txp) {
          return cb(err, txp, memo);
        });
      });
    } else {
      self._doBroadcast(txp, cb);
    }
  });
};

API.prototype.buildTx = function(txp) {
  var self = this;
  var t = new self.ctx.Transaction();

  $.checkState(lodash.includes(lodash.values(Constants.SCRIPT_TYPES), txp.addressType));

  switch (txp.addressType) {
    case Constants.SCRIPT_TYPES.P2SH:
      lodash.each(txp.inputs, function(i) {
        t.from(i, i.publicKeys, txp.requiredSignatures);
      });
      break;
    case Constants.SCRIPT_TYPES.P2PKH:
      t.from(txp.inputs);
      break;
  }

  if (txp.toAddress && txp.amount && !txp.outputs) {
    t.to(txp.toAddress, txp.amount);
  } else if (txp.outputs) {
    lodash.each(txp.outputs, function(o) {
      $.checkState(o.script || o.toAddress, 'Output should have either toAddress or script specified');
      if (o.script) {

        var out = {};
        out.script = o.script;
        out[self.Unit().atomicsAccessor()] = o.amount;

        t.addOutput(new self.ctx.Transaction.Output(out));
      } else {
        t.to(o.toAddress, o.amount);
      }
    });
  }

  t.fee(txp.fee);
  t.change(txp.changeAddress.address);

  // Shuffle outputs for improved privacy
  if (t.outputs.length > 1) {
    var outputOrder = lodash.reject(txp.outputOrder, function(order) {
      return order >= t.outputs.length;
    });
    $.checkState(t.outputs.length == outputOrder.length);
    t.sortOutputs(function(outputs) {
      return lodash.map(outputOrder, function(i) {
        return outputs[i];
      });
    });
  }

  // Validate inputs vs outputs independently.
  var totalInputs = lodash.reduce(txp.inputs, function(memo, i) {
    return +i[self.Unit().atomicsAccessor()] + memo;
  }, 0);
  var totalOutputs = lodash.reduce(t.outputs, function(memo, o) {
    return +o[self.Unit().atomicsAccessor()] + memo;
  }, 0);

  $.checkState(totalInputs - totalOutputs >= 0);
  $.checkState(totalInputs - totalOutputs <= self.ctx.Defaults.MAX_TX_FEE);

  return t;
};

API.prototype.buildTxFromPrivateKey = function(privateKey, destinationAddress, opts, cb) {
  var self = this;
  opts = opts || {};
  var privateKey = new PrivateKey(privateKey);
  var address = self.ctx.Address.fromPublicKey(privateKey.publicKey);

  async.waterfall([
    function(next) {
      self.getUtxos({
        addresses: address.toString(),
      }, function(err, utxos) {
        return next(err, utxos);
      });
    },
    function(utxos, next) {
      if (!lodash.isArray(utxos) || utxos.length == 0) {
        return next(new Error('No utxos found'));
      }

      var fee = opts.fee || 10000;
      var amount = lodash.sumBy(utxos, self.Unit().atomicsAccessor()) - fee;
      if (amount <= 0) {
        return next(new Errors.INSUFFICIENT_FUNDS);
      }

      var tx;
      try {
        var toAddress = self.ctx.Address.fromString(destinationAddress);

        tx = new self.ctx.Transaction()
          .from(utxos)
          .to(toAddress, amount)
          .fee(fee)
          .sign(privateKey);

        // Make sure the tx can be serialized
        tx.serialize();

      } catch (ex) {
        self.log.error('Could not build transaction from private key', ex);
        return next(new Errors.COULD_NOT_BUILD_TRANSACTION);
      }
      return next(null, tx);
    }
  ], cb);
};

/**
 * Can this credentials sign a transaction?
 * (Only returns fail on a 'proxy' setup for airgapped operation)
 *
 * @return {undefined}
 */
API.prototype.canSign = function() {
  return this.credentials && this.credentials.canSign();
};

/**
 * Create a transaction proposal
 *
 * @param {Object} opts
 * @param {string} opts.txProposalId - Optional. If provided it will be used as this TX proposal ID. Should be unique in the scope of the wallet.
 * @param {Array} opts.outputs - List of outputs.
 * @param {string} opts.outputs[].toAddress - Destination address.
 * @param {number} opts.outputs[].amount - Amount to transfer in atomic units.
 * @param {string} opts.outputs[].message - A message to attach to this output.
 * @param {string} opts.message - A message to attach to this transaction.
 * @param {number} opts.feeLevel[='normal'] - Optional. Specify the fee level for this TX ('priority', 'normal', 'economy', 'superEconomy').
 * @param {number} opts.feePerKb - Optional. Specify the fee per KB for this TX (in atomic units).
 * @param {string} opts.changeAddress - Optional. Use this address as the change address for the tx. The address should belong to the wallet. In the case of singleAddress wallets, the first main address will be used.
 * @param {Boolean} opts.sendMax - Optional. Send maximum amount of funds that make sense under the specified fee/feePerKb conditions. (defaults to false).
 * @param {string} opts.payProUrl - Optional. Paypro URL for peers to verify TX
 * @param {Boolean} opts.excludeUnconfirmedUtxos[=false] - Optional. Do not use UTXOs of unconfirmed transactions as inputs
 * @param {Boolean} opts.validateOutputs[=true] - Optional. Perform validation on outputs.
 * @param {Boolean} opts.dryRun[=false] - Optional. Simulate the action but do not change server state.
 * @param {Array} opts.inputs - Optional. Inputs for this TX
 * @param {number} opts.fee - Optional. Use an fixed fee for this TX (only when opts.inputs is specified)
 * @param {Boolean} opts.noShuffleOutputs - Optional. If set, TX outputs won't be shuffled. Defaults to false
 * @returns {Callback} cb - Return error or the transaction proposal
 */
API.prototype.createTxProposal = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials && self.isComplete());
    $.checkState(self.credentials.sharedEncryptingKey);
  } catch (e) {
    return cb(e);
  }

  $.checkArgument(opts);

  var args = self._getCreateTxProposalArgs(opts);

  self._doPostRequest('/v1/txproposals/', args, function(err, txp) {
    if (err) {
      return cb(err);
    }

    self._processTxps(txp);

    if (!self.verifier.checkProposalCreation(args, txp, self.credentials.sharedEncryptingKey)) {
      return cb(new Errors.SERVER_COMPROMISED);
    }

    return cb(null, txp);
  });
};

/**
 * Edit a note associated with the specified txid
 * @param {Object} opts
 * @param {string} opts.txid - The txid to associate this note with
 * @param {string} opts.body - The contents of the note
 */
API.prototype.editTxNote = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }

  opts = opts || {};

  if (opts.body) {
    opts.body = self._encryptMessage(opts.body, self.credentials.sharedEncryptingKey);
  }

  self._doPutRequest('/v1/txnotes/' + opts.txid + '/', opts, function(err, note) {
    if (err) {
      return cb(err);
    }
    self._processTxNotes(note);
    return cb(null, note);
  });
};

API.prototype.getRawTx = function(txp) {
  var self = this;
  var t = self.buildTx(txp);
  return t.uncheckedSerialize();
};

/**
 * getTx
 *
 * @param {String} TransactionId
 * @return {Callback} cb - Return error or transaction
 */
API.prototype.getTx = function(id, cb) {
  var self = this;
  try{
    $.checkState(self.isComplete());
  } catch (e) {
    return cb(e);
  }

  var url = '/v1/txproposals/' + id;
  self._doGetRequest(url, function(err, txp) {
    if (err) {
      return cb(err);
    }

    self._processTxps(txp);
    return cb(null, txp);
  });
};

/**
 * Get transaction history
 *
 * @param {Object} opts
 * @param {Number} opts.skip (defaults to 0)
 * @param {Number} opts.limit
 * @param {Boolean} opts.includeExtendedInfo
 * @param {Callback} cb
 * @return {Callback} cb - Return error or array of transactions
 */
API.prototype.getTxHistory = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.isComplete());
  } catch (e) {
    return cb(e);
  }

  var args = [];

  if (opts) {
    if (opts.skip) {
      args.push('skip=' + opts.skip);
    }

    if (opts.limit) {
      args.push('limit=' + opts.limit);
    }

    if (opts.includeExtendedInfo) {
      args.push('includeExtendedInfo=1');
    }
  }

  var qs = '';
  if (args.length > 0) {
    qs = '?' + args.join('&');
  }

  var url = '/v1/txhistory/' + qs;
  self._doGetRequest(url, function(err, txs) {
    if (err) {
      return cb(err);
    }
    self._processTxps(txs);
    return cb(null, txs);
  });
};

/**
 * Get a note associated with the specified txid
 * @param {Object} opts
 * @param {string} opts.txid - The txid to associate this note with
 */
API.prototype.getTxNote = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }

  opts = opts || {};

  self._doGetRequest('/v1/txnotes/' + opts.txid + '/', function(err, note) {
    if (err) {
      return cb(err);
    }
    self._processTxNotes(note);
    return cb(null, note);
  });
};

/**
 * Get all notes edited after the specified date
 * @param {Object} opts
 * @param {string} opts.minTs - The starting timestamp
 */
API.prototype.getTxNotes = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }

  opts = opts || {};
  var args = [];

  if (lodash.isNumber(opts.minTs)) {
    args.push('minTs=' + opts.minTs);
  }

  var qs = '';
  if (args.length > 0) {
    qs = '?' + args.join('&');
  }

  self._doGetRequest('/v1/txnotes/' + qs, function(err, notes) {
    if (err) {
      return cb(err);
    }
    self._processTxNotes(notes);
    return cb(null, notes);
  });
};

/**
 * Get list of transactions proposals
 *
 * @param {Object} opts
 * @param {Boolean} opts.doNotVerify
 * @param {Boolean} opts.forAirGapped
 * @param {Boolean} opts.doNotEncryptPkr
 * @return {Callback} cb - Return error or array of transactions proposals
 */
API.prototype.getTxProposals = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.isComplete());
  } catch (e) {
    return cb(e);
  }

  self._doGetRequest('/v1/txproposals/', function(err, txps) {
    if (err) {
      return cb(err);
    }
    self._processTxps(txps);
    async.every(txps,
      function(txp, acb) {
        if (opts.doNotVerify) {
          return acb(true);
        }

        self.getPayPro(txp, function(err, paypro) {
          var isLegit = self.verifier.checkTxProposal(self.credentials, txp, {
            paypro: paypro,
          });

          return acb(isLegit);
        });
      },
      function(isLegit) {
        if (!isLegit) {
          return cb(new Errors.SERVER_COMPROMISED);
        }

        var result;
        if (opts.forAirGapped) {
          result = {
            txps: JSON.parse(JSON.stringify(txps)),
            encryptedPkr: opts.doNotEncryptPkr ? null : self.ctx.Utils.encryptMessage(JSON.stringify(self.credentials.publicKeyRing), self.credentials.personalEncryptingKey),
            unencryptedPkr: opts.doNotEncryptPkr ? JSON.stringify(self.credentials.publicKeyRing) : null,
            m: self.credentials.m,
            n: self.credentials.n,
          };
        } else {
          result = txps;
        }
        return cb(null, result);
      });
  });
};

/**
 * Gets list of utxos
 *
 * @param {Function} cb
 * @param {Object} opts
 * @param {Array} opts.addresses (optional) - List of addresses from where to fetch UTXOs.
 * @returns {Callback} cb - Return error or the list of utxos
 */
API.prototype.getUtxos = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.isComplete());
  } catch (e) {
    return cb(e);
  }

  opts = opts || {};
  var url = '/v1/utxos/';

  if (opts.addresses) {
    url += '?' + querystring.stringify({
      addresses: [].concat(opts.addresses).join(',')
    });
  }

  self._doGetRequest(url, cb);
};

/**
 * Publish a transaction proposal
 *
 * @param {Object} opts
 * @param {Object} opts.txp - The transaction proposal object returned by the API#createTxProposal method
 * @returns {Callback} cb - Return error or null
 */
API.prototype.publishTxProposal = function(opts, cb) {
  var self = this;
  $.checkArgument(opts)
    .checkArgument(opts.txp);

  try{
    $.checkState(self.isComplete());
    $.checkState(parseInt(opts.txp.version) >= 3);
  } catch (e) {
    return cb(e);
  }

  var t = self.buildTx(opts.txp);
  var hash = t.uncheckedSerialize();
  var args = {
    proposalSignature: self.ctx.Utils.signMessage(hash, self.credentials.requestPrivKey)
  };

  var url = '/v1/txproposals/' + opts.txp.id + '/publish/';
  self._doPostRequest(url, args, function(err, txp) {
    if (err) {
      return cb(err);
    }
    self._processTxps(txp);
    return cb(null, txp);
  });
};

/**
 * Reject a transaction proposal
 *
 * @param {Object} txp
 * @param {String} reason
 * @param {Callback} cb
 * @return {Callback} cb - Return error or object
 */
API.prototype.rejectTxProposal = function(txp, reason, cb) {
  var self = this;
  try{
    $.checkState(self.isComplete());
  } catch (e) {
    return cb(e);
  }

  $.checkArgument(cb);

  var url = '/v1/txproposals/' + txp.id + '/rejections/';
  var args = {
    reason: self._encryptMessage(reason, self.credentials.sharedEncryptingKey) || '',
  };

  self._doPostRequest(url, args, function(err, txp) {
    if (err) {
      return cb(err);
    }
    self._processTxps(txp);
    return cb(null, txp);
  });
};

/**
 * Remove a transaction proposal
 *
 * @param {Object} txp
 * @param {Callback} cb
 * @return {Callback} cb - Return error or empty
 */
API.prototype.removeTxProposal = function(txp, cb) {
  var self = this;
  try{
    $.checkState(self.isComplete());
  } catch (e) {
    return cb(e);
  }

  var url = '/v1/txproposals/' + txp.id;

  self._doDeleteRequest(url, function(err) {
    return cb(err);
  });
};

API.prototype.signTxp = function(txp, derivedXPrivKey) {
  var self = this;
  //Derive proper key to sign, for each input
  var privs = [];
  var derived = {};

  var xpriv = new HDPrivateKey(derivedXPrivKey);

  lodash.each(txp.inputs, function(i) {
    $.checkState(i.path, "Input derivation path not available (signing transaction)");

    if (!derived[i.path]) {
      derived[i.path] = xpriv.deriveChild(i.path).privateKey;
      privs.push(derived[i.path]);
    }
  });

  var t = self.buildTx(txp);

  var signatures = lodash.map(privs, function(priv, i) {
    return t.getSignatures(priv);
  });

  signatures = lodash.map(lodash.sortBy(lodash.flatten(signatures), 'inputIndex'), function(s) {
    return s.signature.toDER().toString('hex');
  });

  return signatures;
};

/**
 * Sign a transaction proposal
 *
 * @param {Object} txp
 * @param {String} password - (optional) A password to decrypt the encrypted private key (if encryption is set).
 * @param {Callback} cb
 * @return {Callback} cb - Return error or object
 */
API.prototype.signTxProposal = function(txp, password, cb) {
  var self = this;
  try{
    $.checkState(self.isComplete());
  } catch (e) {
    return cb(e);
  }

  $.checkArgument(txp.creatorId);

  if (lodash.isFunction(password)) {
    cb = password;
    password = null;
  }

  if (!txp.signatures) {
    if (!self.canSign()) {
      return cb(new Errors.MISSING_PRIVATE_KEY);
    }

    if (self.isPrivKeyEncrypted() && !password) {
      return cb(new Errors.ENCRYPTED_PRIVATE_KEY);
    }
  }

  self.getPayPro(txp, function(err, paypro) {
    if (err) {
      return cb(err);
    }

    var isLegit = self.verifier.checkTxProposal(self.credentials, txp, {
      paypro: paypro,
    });

    if (!isLegit) {
      return cb(new Errors.SERVER_COMPROMISED);
    }

    var signatures = txp.signatures;

    if (lodash.isEmpty(signatures)) {
      try {
        signatures = self._signTxp(txp, password);
      } catch (ex) {
        self.log.error('Error signing tx', ex);
        return cb(ex);
      }
    }

    var url = '/v1/txproposals/' + txp.id + '/signatures/';
    var args = {
      signatures: signatures
    };

    self._doPostRequest(url, args, function(err, txp) {
      if (err) {
        return cb(err);
      }
      self._processTxps(txp);
      return cb(null, txp);
    });
  });
};

/**
 * Sign transaction proposal from AirGapped
 *
 * @param {Object} txp
 * @param {String} encryptedPkr
 * @param {Number} m
 * @param {Number} n
 * @param {String} password - (optional) A password to decrypt the encrypted private key (if encryption is set).
 * @return {Object} txp - Return transaction
 */
API.prototype.signTxProposalFromAirGapped = function(txp, encryptedPkr, m, n, password) {
  var self = this;
  $.checkState(self.credentials);

  if (!self.canSign()) {
    throw new Errors.MISSING_PRIVATE_KEY;
  }

  if (self.isPrivKeyEncrypted() && !password) {
    throw new Errors.ENCRYPTED_PRIVATE_KEY;
  }

  var publicKeyRing;
  try {
    publicKeyRing = JSON.parse(self.ctx.Utils.decryptMessage(encryptedPkr, self.credentials.personalEncryptingKey));
  } catch (ex) {
    throw new Error('Could not decrypt public key ring');
  }

  if (!lodash.isArray(publicKeyRing) || publicKeyRing.length != n) {
    throw new Error('Invalid public key ring');
  }

  self.credentials.extend({
    m: m,
    n: n,
    addressType: txp.addressType
  });
//  self.credentials.m = m;
//  self.credentials.n = n;
//  self.credentials.addressType = txp.addressType;
  self.credentials.addPublicKeyRing(publicKeyRing);

  if (!self.verifier.checkTxProposalSignature(self.credentials, txp)) {
    throw new Error('Fake transaction proposal');
  }

  return self._signTxp(txp, password);
};

/**
 * Sign transaction proposal from AirGapped
 *
 * @param {String} key - A mnemonic phrase or an extended HD private key
 * @param {Object} txp
 * @param {String} unencryptedPkr
 * @param {Number} m
 * @param {Number} n
 * @param {Object} opts
 * @param {String} opts.passphrase
 * @param {Number} opts.account - default 0
 * @param {String} opts.derivationStrategy - default 'BIP44'
 * @return {Object} txp - Return transaction
 */
API.prototype.signTxProposalFromAirGappedWithNewClient = function(key, txp, unencryptedPkr, m, n, opts) {
  var self = this;
  opts = opts || {};

  var publicKeyRing = JSON.parse(unencryptedPkr);

  if (!lodash.isArray(publicKeyRing) || publicKeyRing.length != n) {
    throw new Error('Invalid public key ring');
  }

  var newClient = new API({
    baseUrl: 'https://ws.example.com/ws/api'
  });

  var xprivPrefixLivenet = Networks.livenet.version.xprivkey.text;
  var xprivPrefixTestnet = Networks.testnet.version.xprivkey.text;

  if (key.slice(0, 4) === xprivPrefixLivenet || key.slice(0, 4) === xprivPrefixTestnet) {
    if (key.slice(0, 4) === xprivPrefixLivenet && txp.networkName == self.TESTNET.name) {
      throw new Error('testnet HD keys must start with ' + xprivPrefixTestnet);
    }
    if (key.slice(0, 4) === xprivPrefixTestnet && txp.networkName == self.LIVENET.name) {
      throw new Error('livenet HD keys must start with ' + xprivPrefixLivenet);
    }
    newClient.seedFromExtendedPrivateKey(key, {
      'account': opts.account,
      'derivationStrategy': opts.derivationStrategy
    });
  } else {
    newClient.seedFromMnemonic(key, {
      networkName: txp.networkName,
      passphrase: opts.passphrase,
      account: opts.account,
      derivationStrategy: opts.derivationStrategy
    })
  }

  newClient.credentials.extend({
    m: m,
    n: n,
    addressType: txp.addressType
  });
//  newClient.credentials.m = m;
//  newClient.credentials.n = n;
//  newClient.credentials.addressType = txp.addressType;
  newClient.credentials.addPublicKeyRing(publicKeyRing);

  if (!self.verifier.checkTxProposalSignature(newClient.credentials, txp)) {
    throw new Error('Fake transaction proposal');
  }

  return newClient._signTxp(txp);
};

API.prototype._addSignaturesToTx = function(txp, t, signatures, xpub) {
  if (signatures.length != txp.inputs.length)
    throw new Error('Number of signatures does not match number of inputs');

  var i = 0;
  var x = new HDPublicKey(xpub);

  lodash.each(signatures, function(signatureHex) {
    var input = txp.inputs[i];

    try {
      var signature = Signature.fromString(signatureHex);
      var pub = x.deriveChild(txp.inputPaths[i]).publicKey;
      var s = {
        inputIndex: i,
        signature: signature,
        sigtype: Signature.SIGHASH_ALL,
        publicKey: pub,
      };
      t.inputs[i].addSignature(t, s);
      i++;
    } catch (e) {};
  });

  if (i != txp.inputs.length) {
    throw new Error('Wrong signatures');
  }
};

API.prototype._applyAllSignatures = function(txp, t) {
  var self = this;
  $.checkState(txp.status == 'accepted');

  var sigs = self._getCurrentSignatures(txp);

  lodash.each(sigs, function(x) {
    self._addSignaturesToTx(txp, t, x.signatures, x.xpub);
  });
};

API.prototype._doBroadcast = function(txp, cb) {
  var self = this;
  var url = '/v1/txproposals/' + txp.id + '/broadcast/';

  self._doPostRequest(url, {}, function(err, txp) {
    if (err) {
      return cb(err);
    }
    self._processTxps(txp);
    return cb(null, txp);
  });
};

API.prototype._getCreateTxProposalArgs = function(opts) {
  var self = this;

  var args = lodash.cloneDeep(opts);
  args.message = self._encryptMessage(opts.message, self.credentials.sharedEncryptingKey) || null;
  args.payProUrl = opts.payProUrl || null;

  lodash.each(args.outputs, function(o) {
    o.message = self._encryptMessage(o.message, self.credentials.sharedEncryptingKey) || null;
  });

  return args;
};

API.prototype._getCurrentSignatures = function(txp) {
  var acceptedActions = lodash.filter(txp.actions, {
    type: 'accept'
  });

  return lodash.map(acceptedActions, function(x) {
    return {
      signatures: x.signatures,
      xpub: x.xpub,
    };
  });
};

API.prototype._processTxNotes = function(notes) {
  var self = this;

  if (!notes) {
    return;
  }

  var encryptingKey = self.credentials.sharedEncryptingKey;
  lodash.each([].concat(notes), function(note) {
    note.encryptedBody = note.body;
    note.body = self._decryptMessage(note.body, encryptingKey);
    note.encryptedEditedByName = note.editedByName;
    note.editedByName = self._decryptMessage(note.editedByName, encryptingKey);
  });
};

/**
 * Decrypt text fields in transaction proposals
 * @private
 * @static
 * @memberof Client.API
 * @param {Array} txps
 * @param {String} encryptingKey
 */
API.prototype._processTxps = function(txps) {
  var self = this;
  if (!txps) {
    return;
  }

  var encryptingKey = self.credentials.sharedEncryptingKey;
  lodash.each([].concat(txps), function(txp) {
    txp.encryptedMessage = txp.message;
    txp.message = self._decryptMessage(txp.message, encryptingKey) || null;
    txp.creatorName = self._decryptMessage(txp.creatorName, encryptingKey);

    lodash.each(txp.actions, function(action) {
      action.copayerName = self._decryptMessage(action.copayerName, encryptingKey);
      action.comment = self._decryptMessage(action.comment, encryptingKey);
      // TODO get copayerName from Credentials -> copayerId to copayerName
      // action.copayerName = null;
    });

    lodash.each(txp.outputs, function(output) {
      output.encryptedMessage = output.message;
      output.message = self._decryptMessage(output.message, encryptingKey) || null;
    });

    txp.hasUnconfirmedInputs = lodash.some(txp.inputs, function(input) {
      return input.confirmations == 0;
    });

    self._processTxNotes(txp.note);
  });
};

API.prototype._signTxp = function(txp, password) {
  var self = this;
  var derived = self.credentials.getDerivedXPrivKey(password);
  return self.signTxp(txp, derived);
};

/**************************************************
 *
 * Payment Protocol
 *
 **************************************************/

/**
 * fetchPayPro
 *
 * @param opts.payProUrl  URL for paypro request
 * @returns {Callback} cb - Return error or the parsed payment protocol request
 * Returns (err,paypro)
 *  paypro.amount
 *  paypro.toAddress
 *  paypro.memo
 */
API.prototype.fetchPayPro = function(opts, cb) {
  var self = this;
  $.checkArgument(opts)
    .checkArgument(opts.payProUrl);

  self.paypro.get({
    url: opts.payProUrl,
    http: self.payProHttp,
  }, function(err, paypro) {
    if (err) {
      return cb(err);
    }

    return cb(null, paypro);
  });
};

API.prototype.getPayPro = function(txp, cb) {
  var self = this;
  if (!txp.payProUrl || self.doNotVerifyPayPro) {
    return cb();
  }

  self.paypro.get({
    url: txp.payProUrl,
    http: self.payProHttp,
  }, function(err, paypro) {
    if (err) {
      return cb(new Error('Cannot check transaction now:' + err));
    }
    return cb(null, paypro);
  });
};

/**************************************************
 *
 * Notifications
 *
 **************************************************/

/**
 * Get latest notifications
 *
 * @param {object} opts
 * @param {String} opts.lastNotificationId (optional) - The ID of the last received notification
 * @param {String} opts.timeSpan (optional) - A time window on which to look for notifications (in seconds)
 * @param {String} opts.includeOwn[=false] (optional) - Do not ignore notifications generated by the current copayer
 * @returns {Callback} cb - Returns error or an array of notifications
 */
API.prototype.getNotifications = function(opts, cb) {
  var self = this;
  try{
    $.checkState(self.credentials);
  } catch (e) {
    return cb(e);
  }

  opts = opts || {};

  var url = '/v1/notifications/';
  if (opts.lastNotificationId) {
    url += '?notificationId=' + opts.lastNotificationId;
  } else if (opts.timeSpan) {
    url += '?timeSpan=' + opts.timeSpan;
  }

  self._doGetRequestWithLogin(url, function(err, result) {
    if (err) {
      return cb(err);
    }

    var notifications = lodash.filter(result, function(notification) {
      return opts.includeOwn || (notification.creatorId != self.credentials.copayerId);
    });

    return cb(null, notifications);
  });
};

/**
 * Subscribe to push notifications.
 * @param {Object} opts
 * @param {String} opts.type - Device type (ios or android).
 * @param {String} opts.token - Device token.
 * @returns {Object} response - Status of subscription.
 */
API.prototype.pushNotificationsSubscribe = function(opts, cb) {
  var self = this;
  var url = '/v1/pushnotifications/subscriptions/';
  self._doPostRequest(url, opts, function(err, response) {
    if (err) {
      return cb(err);
    }
    return cb(null, response);
  });
};

/**
 * Unsubscribe from push notifications.
 * @param {String} token - Device token
 * @return {Callback} cb - Return error if exists
 */
API.prototype.pushNotificationsUnsubscribe = function(token, cb) {
  var self = this;
  var url = '/v1/pushnotifications/subscriptions/' + token;
  self._doDeleteRequest(url, cb);
};

/**
 * Reset notification polling with new interval
 * @param {Numeric} notificationIntervalSeconds - use 0 to pause notifications
 */
API.prototype.setNotificationsInterval = function(notificationIntervalSeconds) {
  var self = this;
  self._disposeNotifications();

  if (notificationIntervalSeconds > 0) {
    self._initNotifications({
      notificationIntervalSeconds: notificationIntervalSeconds
    });
  }
};

/**
 * Listen to a tx for its first confirmation.
 * @param {Object} opts
 * @param {String} opts.txid - The txid to subscribe to.
 * @returns {Object} response - Status of subscription.
 */
API.prototype.txConfirmationSubscribe = function(opts, cb) {
  var self = this;
  var url = '/v1/txconfirmations/';
  self._doPostRequest(url, opts, function(err, response) {
    if (err) {
      return cb(err);
    }
    return cb(null, response);
  });
};

/**
 * Stop listening for a tx confirmation.
 * @param {String} txid - The txid to unsubscribe from.
 * @return {Callback} cb - Return error if exists
 */
API.prototype.txConfirmationUnsubscribe = function(txid, cb) {
  var self = this;
  var url = '/v1/txconfirmations/' + txid;
  self._doDeleteRequest(url, cb);
};

API.prototype._disposeNotifications = function() {
  var self = this;

  if (self.notificationsIntervalId) {
    clearInterval(self.notificationsIntervalId);
    self.notificationsIntervalId = null;
  }
};

API.prototype._fetchLatestNotifications = function(interval, cb) {
  var self = this;

  cb = cb || function() {};

  var opts = {
    lastNotificationId: self.lastNotificationId,
    includeOwn: self.notificationIncludeOwn,
  };

  if (!self.lastNotificationId) {
    opts.timeSpan = interval + 1;
  }

  self.getNotifications(opts, function(err, notifications) {
    if (err) {
      self.log.error('Error receiving notifications.', err);
      return cb(err);
    }

    if (notifications.length > 0) {
      self.lastNotificationId = lodash.last(notifications).id;
    }

    lodash.each(notifications, function(notification) {
      self.emit('notification', notification);
    });

    return cb();
  });
};

API.prototype._initNotifications = function(opts) {
  var self = this;

  opts = opts || {};

  var interval = opts.notificationIntervalSeconds || 5;

  self.notificationsIntervalId = setInterval(function() {
    self._fetchLatestNotifications(interval, function(err) {
      if (err) {
        if (err instanceof Errors.NOT_FOUND || err instanceof Errors.UNAUTHORIZED) {
          self._disposeNotifications();
        }
      }
    });
  }, interval * 1000);
};

/**************************************************
 *
 * Exchange Rates
 *
 **************************************************/

/**
 * Get current fee levels for the specified network name
 *
 * @param {string} networkName - LIVENET.name (default) or TESTNET.name
 * @param {Callback} cb
 * @returns {Callback} cb - Returns error or an object with status information
 */
API.prototype.getFeeLevels = function(networkName, cb) {
  var self = this;

  $.checkArgument(networkName || lodash.includes([self.LIVENET.name, self.TESTNET.name], networkName));
  networkName = networkName || self.LIVENET.name;

  self._doGetRequest('/v1/feelevels/' + networkName, function(err, result) {
    if (err) {
      return cb(err);
    }
    return cb(err, result);
  });
};

/**
 * Returns exchange rate for the specified currency, (fiat ISO) code, and timestamp.
 * @param {Object} opts
 * @param {string} opts.currency - Blockchain currency code (e.g., 'BTC').
 * @param {string} opts.code - Currency ISO code.
 * @param {Date} [opts.ts] - A timestamp to base the rate on (default Date.now()).
 * @param {String} [opts.provider] - A provider of exchange rates.
 * @returns {Object} rates - The exchange rate.
 */
API.prototype.getFiatRate = function(opts, cb) {
  var self = this;
  $.checkArgument(cb);

  var opts = opts || {};
  var args = [];

  if (opts.ts) {
    args.push('ts=' + opts.ts);
  }

  if (opts.provider) {
    args.push('provider=' + opts.provider);
  }

  var qs = '';
  if (args.length > 0) {
    qs = '?' + args.join('&');
  }

  self._doGetRequest('/v1/fiatrates/' + opts.currency + '/' + opts.code + '/' + qs, function(err, rates) {
    if (err) {
      return cb(err);
    }
    return cb(null, rates);
  });
};

/**************************************************
 *
 * Message Encryption
 *
 **************************************************/

/**
 * Encrypt a message
 * @private
 * @static
 * @memberof Client.API
 * @param {String} message
 * @param {String} encryptingKey
 */
API.prototype._encryptMessage = function(message, encryptingKey) {
  var self = this;
  if (!message) {
    return null;
  }
  return self.ctx.Utils.encryptMessage(message, encryptingKey);
};

/**
 * Decrypt a message
 * @private
 * @static
 * @memberof Client.API
 * @param {String} message
 * @param {String} encryptingKey
 */
API.prototype._decryptMessage = function(message, encryptingKey) {
  var self = this;
  if (!message) {
    return '';
  }
  try {
    return self.ctx.Utils.decryptMessage(message, encryptingKey);
  } catch (ex) {
    return '<ECANNOTDECRYPT>';
  }
};

/**************************************************
 *
 * Utilities
 *
 **************************************************/

API.prototype.formatAmount = function(atomics, unit, opts) {
  return this.utils.formatAmount(atomics, unit, opts);
};

/**************************************************
 *
 * HTTP Request Handling
 *
 **************************************************/

/**
 * Do a DELETE request
 * @private
 *
 * @param {String} url
 * @param {Callback} cb
 */
API.prototype._doDeleteRequest = function(url, cb) {
  return this._doRequest('delete', url, {}, false, cb);
};

/**
 * Do an HTTP request
 * @private
 *
 * @param {Object} method
 * @param {String} url
 * @param {Object} args
 * @param {Callback} cb
 */
API.prototype._doRequest = function(method, url, args, useSession, cb) {
  var self = this;

  function setUrl(url) {
    if (url.charAt(url.length-1) == '/') {
      url = url.substring(0, url.length - 1);
    }

    if (url.indexOf('?') >= 0) {
      url += '&';
    } else {
      url += '?';
    }

    url += 'service=' + self.LIVENET.name; // Livenet name is used to id the service
    return url;
  };

  url = setUrl(url);
  var headers = self._getHeaders(method, url, args);

  if (self.credentials) {
    headers['x-identity'] = self.credentials.copayerId;

    if (useSession && self.session) {
      headers['x-session'] = self.session;
    } else {
      var reqSignature;
      var key = args._requestPrivKey || self.credentials.requestPrivKey;
      if (key) {
        delete args['_requestPrivKey'];
        reqSignature = self._signRequest(method, url, args, key);
      }
      headers['x-signature'] = reqSignature;
    }
  }

  var r = self.request[method](self.baseUrl + url);

  r.accept('json');

  lodash.each(headers, function(v, k) {
    if (v) {
      r.set(k, v);
    }
  });

  if (args) {
    if (method == 'post' || method == 'put') {
      r.send(args);
    } else {
      r.query(args);
    }
  }

  r.timeout(self.timeout);

  r.end(function(err, res) {
    if (!res) {
      return cb(new Errors.CONNECTION_ERROR);
    }

    if (!lodash.isEmpty(res.body)) {
      self.log.debug(util.inspect(res.body, {
        depth: 10
      }));
    }

    if (!lodash.inRange(res.status, 199, 300)) {
      if (res.status === 404) {
        return cb(new Errors.NOT_FOUND);
      }

      if (res.status === 401) {
        return cb(new Errors.UNAUTHORIZED);
      }

      if (lodash.inRange(res.status, 499, 600)) {
        return cb(new Errors.INTERNAL_ERROR(res.statusText || res.body.error));
      }

      if (!res.status) {
        return cb(new Errors.CONNECTION_ERROR);
      }

      self.log.error('HTTP Error: ' + res.status + ' ' +
        res.req.method + ' ' +
        res.req.url + ' - [' + self.LIVENET.currency + ' client] ' + res.body.error);

      if (!res.body) {
        return cb(new Error(res.status));
      }

      return cb(API._parseError(res.body));
    }

    if (res.body === '{"error":"read ECONNRESET"}') {
      return cb(new Errors.ECONNRESET_ERROR(JSON.parse(res.body)));
    }

    return cb(null, res.body, res.header);
  });
};

/**
 * Do an HTTP request
 * @private
 *
 * @param {Object} method
 * @param {String} url
 * @param {Object} args
 * @param {Callback} cb
 */
API.prototype._doRequestWithLogin = function(method, url, args, cb) {
  var self = this;

  function doLogin(cb) {
    self._login(function(err, s) {
      if (err) {
        return cb(err);
      }
      if (!s) {
        return cb(new Errors.UNAUTHORIZED);
      }
      self.session = s;
      cb();
    });
  };

  async.waterfall([
    function(next) {
      if (self.session) {
        return next();
      }
      doLogin(next);
    },
    function(next) {
      self._doRequest(method, url, args, true, function(err, body, header) {
        if (err && err instanceof Errors.UNAUTHORIZED) {
          doLogin(function(err) {
            if (err) {
              return next(err);
            }
            return self._doRequest(method, url, args, true, next);
          });
        }
        next(null, body, header);
      });
    },
  ], cb);
};

/**
 * Do a POST request
 * @private
 *
 * @param {String} url
 * @param {Object} args
 * @param {Callback} cb
 */
API.prototype._doPostRequest = function(url, args, cb) {
  return this._doRequest('post', url, args, false, cb);
};

API.prototype._doPutRequest = function(url, args, cb) {
  return this._doRequest('put', url, args, false, cb);
};

/**
 * Do a GET request
 * @private
 *
 * @param {String} url
 * @param {Callback} cb
 */
API.prototype._doGetRequest = function(url, cb) {
  var self = this;
  url += url.indexOf('?') > 0 ? '&' : '?';
  url += 'r=' + lodash.random(10000, 99999);
  return self._doRequest('get', url, {}, false, cb);
};

API.prototype._doGetRequestWithLogin = function(url, cb) {
  var self = this;
  url += url.indexOf('?') > 0 ? '&' : '?';
  url += 'r=' + lodash.random(10000, 99999);
  return self._doRequestWithLogin('get', url, {}, cb);
};

API.prototype._getHeaders = function(method, url, args) {
  var self = this;
  var headers = {
    'x-client-version': Package.version,
  };
  if (self.supportStaffWalletId) {
    headers['x-wallet-id'] = self.supportStaffWalletId;
  }

  return headers;
};

API.prototype._login = function(cb) {
  this._doPostRequest('/v1/login', {}, cb);
};

API.prototype._logout = function(cb) {
  this._doPostRequest('/v1/logout', {}, cb);
};

/**
 * Sign an HTTP request
 * @private
 * @static
 * @memberof Client.API
 * @param {String} method - The HTTP method
 * @param {String} url - The URL for the request
 * @param {Object} args - The arguments in case this is a POST/PUT request
 * @param {String} privKey - Private key to sign the request
 */
API.prototype._signRequest = function(method, url, args, privKey) {
  var self = this;
  var message = [method.toLowerCase(), url, JSON.stringify(args)].join('|');
  return self.ctx.Utils.signMessage(message, privKey);
};

/**
 * Parse errors
 * @private
 * @static
 * @memberof Client.API
 * @param {Object} body
 */
API._parseError = function(body) {
  if (!body) {
    return;
  }

  if (lodash.isString(body)) {
    try {
      body = JSON.parse(body);
    } catch (e) {
      body = {
        error: body
      };
    }
  }

  var ret;

  if (body.code) {
    if (Errors[body.code]) {
      ret = new Errors[body.code];
      if (body.message) ret.message = body.message;
    } else {
      ret = new Error(body.code + ': ' + body.message);
    }
  } else {
    ret = new Error(body.error || JSON.stringify(body));
  }

  return ret;
};

module.exports = API;
