'use strict;'

var Client = {};

Client.BCH = require('./lib/bch-client');
Client.BTC = require('./lib/btc-client');
Client.LTC = require('./lib/ltc-client');

module.exports = Client;
