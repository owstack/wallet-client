'use strict;'

var baseClient = require('../base-client');
var ltcLib = require('@owstack/ltc-lib');
var API = baseClient;
var Address = ltcLib.Address;
var Defaults = ltcLib.Defaults;
var Networks = ltcLib.Networks;
var Transaction = ltcLib.Transaction;
var Units = ltcLib.Units;
var inherits = require('inherits');

function LtcAPI(opts) {
	var context = {
		Address: Address,
		Defaults: Defaults,
		Networks: Networks,
		Transaction: Transaction,
		Units: Units
	};

  API.apply(this, [context, opts]);
};
inherits(LtcAPI, API);

// Expose all static methods.
Object.keys(API).forEach(function(key) {
  LtcAPI[key] = API[key];
});

module.exports = LtcAPI;
