'use strict';

var lodash = require('@owstack/ows-common').deps.lodash;
var Common = lodash.cloneDeep(require('../../base-client').Common);

Common.Defaults = require('./defaults');
Common.Utils = require('./utils');

module.exports = Common;
