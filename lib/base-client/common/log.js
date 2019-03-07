'use strict';

// A log object should be passed to lib object constructors.

function Log() {};
Log.prototype.debug = function(){};
Log.prototype.info = function(){};
Log.prototype.warn = function(){};
Log.prototype.error = function(){};
Log.prototype.fatal = function(){};

module.exports = new Log();
