'use strict';

var cLib = require('./cLib');

var BaseWalletClient = require('../base-client');
var BasePayPro = BaseWalletClient.PayPro;

var Address = cLib.Address;
var Script = cLib.Script;

var context = {
	Address: Address,
	Script: Script
};

class CPayPro extends BasePayPro {
	constructor() {
	  super(context);
	}
};

module.exports = CPayPro;
