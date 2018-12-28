'use strict;'

var Client = {};

Client.Credentials = require('@owstack/credentials-lib');
Client.errors = require('./lib/base-client').errors;
Client.keyLib = require('@owstack/key-lib');
Client.sjcl = require('sjcl');

Client.networks = {
	BCH: require('./lib/bch-client'),
	BTC: require('./lib/btc-client'),
	LTC: require('./lib/ltc-client')
};

module.exports = Client;
