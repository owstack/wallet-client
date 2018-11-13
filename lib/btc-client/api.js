'use strict;'

var baseClient = require('../base-client');
var btcLib = require('@owstack/btc-lib');
var API = baseClient;
var Address = btcLib.Address;
var Defaults = btcLib.Defaults;
var Networks = btcLib.Networks;
var Transaction = btcLib.Transaction;
var Units = btcLib.Units;
var inherits = require('inherits');

function BtcAPI(opts) {
	var context = {
		Address: Address,
		Defaults: Defaults,
		Networks: Networks,
		Transaction: Transaction,
		Units: Units
	};

  API.apply(this, [context, opts]);
};
inherits(BtcAPI, API);

// Expose all static methods.
Object.keys(API).forEach(function(key) {
  BtcAPI[key] = API[key];
});

module.exports = BtcAPI;
