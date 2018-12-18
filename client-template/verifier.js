'use strict';

var BaseWalletClient = require('../base-client');
var BaseVerifier = BaseWalletClient.Verifier;

var Common = require('./common');
var log = require('./log');
var Utils = Common.Utils;

var context = {
	log: log,
	Utils, Utils
};

class CVerifier extends BaseVerifier {
	constructor(client) {
	  super(context, client);
	}
};

module.exports = CVerifier;
