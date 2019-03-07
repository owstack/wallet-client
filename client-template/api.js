'use strict';

var cLib = require('./cLib');
var owsCommon = require('@owstack/ows-common');
var Context = owsCommon.util.Context;

var BaseWalletClient = require('../base-client');
var BaseAPI = BaseWalletClient.API;

var Address = cLib.Address;
var Defaults = cLib.Defaults;
var Networks = cLib.Networks;
var PayPro = require('./paypro');
var Transaction = cLib.Transaction;
var Unit = cLib.Unit;
var URI = cLib.URI;
var Utils = require('./common/utils');
var Verifier = require('./verifier');

var context = new Context({
	Address: Address,
	Defaults: Defaults,
	Networks: Networks,
	PayPro: PayPro,
	Transaction: Transaction,
	Unit: Unit,
	URI: URI,
	Utils: Utils,
	Verifier: Verifier
});

class CAPI extends BaseAPI {
	constructor(opts) {
	  super(context, opts);
	}
};

module.exports = CAPI;
