'use strict;'

var baseClient = require('../base-client');
var BchAPI = require('./api');
var Verifier = baseClient.Verifier;
var inherits = require('inherits');

function BchVerifier() {
	var context = {
		client: new BchAPI()
	};

  Verifier.apply(this, [context]);
};
inherits(BchVerifier, Verifier);

// Copy all static methods in our object.
Object.keys(Verifier).forEach(function(key) {
  BchVerifier[key] = Verifier[key];
});

module.exports = BchVerifier;
