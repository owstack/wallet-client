'use strict';

var owsCommon = require('@owstack/ows-common');
var lodash = owsCommon.deps.lodash;

var DEFAULT_LOG_LEVEL = 'silent';

/**
 * @desc
 * A simple log that wraps the <tt>console.log</tt> methods when available.
 *
 * Usage:
 * <pre>
 *   log = new Log('my log');
 *   log.setLevel('info');
 *   log.debug('Message!'); // won't show
 *   log.setLevel('debug');
 *   log.debug('Message!', 1); // will show '[debug] ows: Message!, 1'
 * </pre>
 *
 * @param {string} name - a name for the logger. This will show up on every log call.
 * @constructor
 */
var Log = function(name) {
  this.name = name || 'log';
  this.level = DEFAULT_LOG_LEVEL;
};

Log.prototype.getLevels = function() {
  return levels;
};

var levels = {
  'silent': -1,
  'debug': 0,
  'info': 1,
  'log': 2,
  'warn': 3,
  'error': 4,
  'fatal': 5
};

lodash.each(levels, function(level, levelName) {
  if (levelName === 'silent') { // dont create a log.silent() method
    return;
  }
  Log.prototype[levelName] = function() {
    if (this.level === 'silent') {
      return;
    }

    if (level >= levels[this.level]) {

      if (Error.stackTraceLimit && this.level == 'debug') {
        var old = Error.stackTraceLimit;
        Error.stackTraceLimit = 2;
        var stack;

        // this hack is to be compatible with IE11
        try {
          anerror();
        } catch (e) {
          stack = e.stack;
        }
        var lines = stack.split('\n');
        var caller = lines[2];
        caller = ':' + caller.substr(6);
        Error.stackTraceLimit = old;
      }

      var str = '[' + levelName + (caller || '') + '] ' + arguments[0],
        extraArgs,
        extraArgs = [].slice.call(arguments, 1);
      if (console[levelName]) {
        extraArgs.unshift(str);
        console[levelName].apply(console, extraArgs);
      } else {
        if (extraArgs.length) {
          str += JSON.stringify(extraArgs);
        }
        console.log(str);
      }
    }
  };
});

/**
 * @desc
 * Sets the level of a logger. A level can be any bewteen: 'debug', 'info', 'log',
 * 'warn', 'error', and 'fatal'. That order matters: if a logger's level is set to
 * 'warn', calling <tt>level.debug</tt> won't have any effect.
 *
 * @param {string} level - the name of the logging level
 */
Log.prototype.setLevel = function(level) {
  this.level = level;
};

/**
 * @class Log
 * @method debug
 * @desc Log messages at the debug level.
 * @param {*} args - the arguments to be logged.
 */
/**
 * @class Log
 * @method info
 * @desc Log messages at the info level.
 * @param {*} args - the arguments to be logged.
 */
/**
 * @class Log
 * @method log
 * @desc Log messages at an intermediary level called 'log'.
 * @param {*} args - the arguments to be logged.
 */
/**
 * @class Log
 * @method warn
 * @desc Log messages at the warn level.
 * @param {*} args - the arguments to be logged.
 */
/**
 * @class Log
 * @method error
 * @desc Log messages at the error level.
 * @param {*} args - the arguments to be logged.
 */
/**
 * @class Log
 * @method fatal
 * @desc Log messages at the fatal level.
 * @param {*} args - the arguments to be logged.
 */

module.exports = Log;
