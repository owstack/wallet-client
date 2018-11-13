'use strict';

/**
 * The client library for wallet services.
 * @module Client
 */

var BaseClient = require('./api');
var BaseCommon = require('./common');

BaseClient.errors = require('./errors');
BaseClient.log = require('./log');
BaseClient.PayPro = require('./paypro');
BaseClient.sjcl = require('sjcl');
BaseClient.Utils = BaseCommon.Utils;
BaseClient.Verifier = require('./Verifier');

module.exports = BaseClient;
