'use strict;'

var baseClient = require('../base-client');
var btcLib = require('@owstack/btc-lib');
var Address = btcLib.Address;
var PayPro = baseClient.PayPro;
var Script = btcLib.Script;
var inherits = require('inherits');

function BtcPayPro() {
	var context = {
		Address: Address,
		Script: Script
	};

  PayPro.apply(this, [context]);
};
inherits(BtcPayPro, PayPro);

// Expose all static methods.
Object.keys(PayPro).forEach(function(key) {
  BtcPayPro[key] = PayPro[key];
});

module.exports = BtcPayPro;
