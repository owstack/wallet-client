'use strict';

var owsCommon = require('@owstack/ows-common');
var lodash = owsCommon.deps.lodash;

function format(message, args) {
  return message
    .replace('{0}', args[0])
    .replace('{1}', args[1])
    .replace('{2}', args[2]);
};

var traverseNode = function(parent, errorDefinition) {
  var NodeError = function() {
    if (lodash.isString(errorDefinition.message)) {
      this.message = format(errorDefinition.message, arguments);
    } else if (lodash.isFunction(errorDefinition.message)) {
      this.message = errorDefinition.message.apply(null, arguments);
    } else {
      throw new Error('Invalid error definition for ' + errorDefinition.name);
    }
    this.stack = this.message + '\n' + (new Error()).stack;
  };
  NodeError.prototype = Object.create(parent.prototype);
  NodeError.prototype.name = parent.prototype.name + errorDefinition.name;
  parent[errorDefinition.name] = NodeError;
  if (errorDefinition.errors) {
    childDefinitions(NodeError, errorDefinition.errors);
  }
  return NodeError;
};

/* jshint latedef: false */
var childDefinitions = function(parent, childDefinitions) {
  lodash.each(childDefinitions, function(childDefinition) {
    traverseNode(parent, childDefinition);
  });
};
/* jshint latedef: true */

var traverseRoot = function(parent, errorsDefinition) {
  childDefinitions(parent, errorsDefinition);
  return parent;
};

var wc = {};
wc.Error = function() {
  this.message = 'Internal error';
  this.stack = this.message + '\n' + (new Error()).stack;
};
wc.Error.prototype = Object.create(Error.prototype);
wc.Error.prototype.name = 'wc.Error';

var data = require('./spec');
traverseRoot(wc.Error, data);

module.exports = wc.Error;
module.exports.extend = function(spec) {
  return traverseNode(wc.Error, spec);
};
