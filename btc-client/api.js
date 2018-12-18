'use strict';

var cLib = require('./cLib');

var BaseWalletClient = require('../base-client');
var BaseAPI = BaseWalletClient.API;

var Address = cLib.Address;
var Common = require('./common');
var Defaults = cLib.Defaults;
var log = require('./log');
var Networks = cLib.Networks;
var PayPro = require('./paypro');
var Transaction = cLib.Transaction;
var Unit = cLib.Unit;
var Utils = Common.Utils;
var Verifier = require('./verifier');

var context = {
	Address: Address,
	Defaults: Defaults,
	log: log,
	Networks: Networks,
	PayPro: PayPro,
	Transaction: Transaction,
	Unit: Unit,
	Utils: Utils,
	Verifier: Verifier
};

class CAPI extends BaseAPI {
	constructor(opts) {
	  super(context, opts);
	}
};

module.exports = CAPI;
