'use strict';

/**
 * The base library for the wallet client.
 * @module BaseWalletClient
 */

var Client = {};

Client.API = require('./api');
Client.Defaults = require('./common/defaults');
Client.errors = require('./errors');
Client.Log = require('./log');
Client.PayPro = require('./paypro');
Client.sjcl = require('sjcl');
Client.Utils = require('./common/utils');
Client.Verifier = require('./verifier');

module.exports = Client;
