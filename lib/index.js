'use strict';

/**
 * The client library for wallet services.
 * @module Client
 */

var Client = {};

Client.BCH = require('./bch-client');
Client.BTC = require('./btc-client');
Client.LTC = require('./ltc-client');

module.exports = Client;
