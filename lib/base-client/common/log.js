'use strict';

var owsCommon = require('@owstack/ows-common');
var lodash = owsCommon.deps.lodash;

const levels = ['debug', 'info', 'warn', 'error'];
const logId = 'Wallet Client -';

function Log(logger) {
	const self = this;

	self.logger = logger;

	lodash.forEach(levels, function(l) {
		Log.prototype[l] = function() {
			if (self.logger) {
				[].unshift.call(arguments, logId);
				self.logger[l].apply(null, arguments);
			}
		};
	});
};

module.exports = Log;
