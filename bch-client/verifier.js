'use strict';

var BaseWalletClient = require('../base-client');
var BaseVerifier = BaseWalletClient.Verifier;

var log = require('./log');

var context = {
	log: log
};

class CVerifier extends BaseVerifier {
	constructor(client) {
	  super(context, client);
	}
};

module.exports = CVerifier;
