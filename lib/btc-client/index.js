'use strict;'

/**
 * The client library for the Bitcoin wallet service.
 * @module BtcClient
 */

var BaseClient = require('../base-client');
var BtcClient = require('./api');

BtcClient.errors = BaseClient.errors;
BtcClient.log = BaseClient.log;
BtcClient.PayPro = require('./paypro');
BtcClient.Utils = BaseClient.Utils;
BtcClient.Verifier = require('./Verifier');

module.exports = BtcClient;
