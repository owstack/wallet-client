'use strict;'

/**
 * The client library for the Litcoin wallet service.
 * @module LtcClient
 */

var BaseClient = require('../base-client');
var LtcClient = require('./api');

LtcClient.errors = BaseClient.errors;
LtcClient.log = BaseClient.log;
LtcClient.PayPro = require('./paypro');
LtcClient.Utils = BaseClient.Utils;
LtcClient.Verifier = require('./Verifier');

module.exports = LtcClient;
