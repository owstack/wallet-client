'use strict;'

/**
 * The client library for the Bitcoin Cash wallet service.
 * @module BchClient
 */

var BaseClient = require('../base-client');
var BchClient = require('./api');

BchClient.errors = BaseClient.errors;
BchClient.log = BaseClient.log;
BchClient.PayPro = require('./paypro');
BchClient.Utils = BaseClient.Utils;
BchClient.Verifier = require('./Verifier');

module.exports = BchClient;
