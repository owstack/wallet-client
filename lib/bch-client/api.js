'use strict;'

var baseClient = require('../base-client');
var bchLib = require('@owstack/bch-lib');
var API = baseClient;
var Address = bchLib.Address;
var Defaults = bchLib.Defaults;
var Networks = bchLib.Networks;
var Transaction = bchLib.Transaction;
var Units = bchLib.Units;
var inherits = require('inherits');

function BchAPI(opts) {
	var context = {
		Address: Address,
		Defaults: Defaults,
		Networks: Networks,
		Transaction: Transaction,
		Units: Units
	};

  API.apply(this, [context, opts]);
};
inherits(BchAPI, API);

// Expose all static methods.
Object.keys(API).forEach(function(key) {
  BchAPI[key] = API[key];
});

module.exports = BchAPI;
