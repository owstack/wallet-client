'use strict';

var owsCommon = require('@owstack/ows-common');
var Context = owsCommon.util.Context;

var BaseWalletClient = require('../base-client');
var BaseVerifier = BaseWalletClient.Verifier;

var Utils = require('./common/utils');

var context = new Context({
	Utils: Utils
});

class CVerifier extends BaseVerifier {
	constructor(opts, client) {
	  super(context, opts, client);
	}
};

module.exports = CVerifier;
