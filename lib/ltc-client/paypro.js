'use strict;'

var baseClient = require('../base-client');
var ltcLib = require('@owstack/ltc-lib');
var Address = ltcLib.Address;
var PayPro = baseClient.PayPro;
var Script = ltcLib.Script;
var inherits = require('inherits');

function LtcPayPro() {
	var context = {
		Address: Address,
		Script: Script
	};

  PayPro.apply(this, [context]);
};
inherits(LtcPayPro, PayPro);

// Expose all static methods.
Object.keys(PayPro).forEach(function(key) {
  LtcPayPro[key] = PayPro[key];
});

module.exports = LtcPayPro;
