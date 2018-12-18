'use strict';

/**
 * The base library for the wallet client.
 * @module BaseWalletClient
 */

var Client = {};

Client.API = require('./api');
Client.Common = require('./common');
Client.errors = require('./errors');
Client.Log = require('./log');
Client.PayPro = require('./paypro');
Client.sjcl = require('sjcl');
Client.Verifier = require('./verifier');

module.exports = Client;
