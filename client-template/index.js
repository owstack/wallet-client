'use strict';

var lodash = require('@owstack/ows-common').deps.lodash;
var Client = lodash.cloneDeep(require('../base-client'));
var Lib = require('./cLib');

Client.API = require('./api');
Client.Common = require('./common');
Client.log = require('./log');
Client.Networks = Lib.Networks;
Client.PayPro = require('./paypro');
Client.Unit = Lib.Unit;
Client.Verifier = require('./verifier');

module.exports = Client;
