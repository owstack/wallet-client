'use strict;'

var baseClient = require('../base-client');
var LtcAPI = require('./api');
var Verifier = baseClient.Verifier;
var inherits = require('inherits');

function LtcVerifier() {
	var context = {
		client: new LtcAPI()
	};

  Verifier.apply(this, [context]);
};
inherits(LtcVerifier, Verifier);

// Copy all static methods in our object.
Object.keys(Verifier).forEach(function(key) {
  LtcVerifier[key] = Verifier[key];
});

module.exports = LtcVerifier;
