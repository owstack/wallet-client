'use strict';

var owsCommon = require('@owstack/ows-common');
var Context = owsCommon.util.Context;

var BaseWalletClient = require('../base-client');
var BaseVerifier = BaseWalletClient.Verifier;

var Common = require('./common');
var log = require('./log');
var Utils = Common.Utils;

var context = new Context({
	log: log,
	Utils: Utils
});

class CVerifier extends BaseVerifier {
	constructor(client) {
	  super(context, client);
	}
};

module.exports = CVerifier;
