'use strict;'

var baseClient = require('../base-client');
var bchLib = require('@owstack/bch-lib');
var Address = bchLib.Address;
var PayPro = baseClient.PayPro;
var Script = bchLib.Script;
var inherits = require('inherits');

function BchPayPro() {
	var context = {
		Address: Address,
		Script: Script
	};

  PayPro.apply(this, [context]);
};
inherits(BchPayPro, PayPro);

// Expose all static methods.
Object.keys(PayPro).forEach(function(key) {
  BchPayPro[key] = PayPro[key];
});

module.exports = BchPayPro;
