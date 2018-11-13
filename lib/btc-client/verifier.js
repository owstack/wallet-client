'use strict;'

var baseClient = require('../base-client');
var BtcAPI = require('./api');
var Verifier = baseClient.Verifier;
var inherits = require('inherits');

function BtcVerifier() {
	var context = {
		client: new BtcAPI()
	};

  Verifier.apply(this, [context]);
};
inherits(BtcVerifier, Verifier);

// Copy all static methods in our object.
Object.keys(Verifier).forEach(function(key) {
  BtcVerifier[key] = Verifier[key];
});

module.exports = BtcVerifier;
