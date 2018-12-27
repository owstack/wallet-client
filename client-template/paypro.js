'use strict';

var cLib = require('./cLib');
var owsCommon = require('@owstack/ows-common');
var Context = owsCommon.util.Context;

var BaseWalletClient = require('../base-client');
var BasePayPro = BaseWalletClient.PayPro;

var Address = cLib.Address;
var Networks = cLib.Networks;
var Script = cLib.Script;

var context = new Context({
	Address: Address,
	Networks: Networks,
	Script: Script
});

class CPayPro extends BasePayPro {
	constructor() {
	  super(context);
	}
};

module.exports = CPayPro;
