'use strict;'

var Client = {};

Client.Credentials = require('@owstack/credentials-lib');
Client.errors = require('./lib/base-client').errors;
Client.keyLib = require('@owstack/key-lib');
Client.sjcl = require('sjcl');

Client.currencies = {
	// Currency names, see https://github.com/owstack/network-lib/blob/master/lib/networks.js (network.currency).
	BCH: require('./lib/bch-client'),
	BTC: require('./lib/btc-client'),
	LTC: require('./lib/ltc-client')
};

module.exports = Client;
