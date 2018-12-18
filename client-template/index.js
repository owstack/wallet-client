'use strict';

var lodash = require('@owstack/ows-common').deps.lodash;
var Client = lodash.cloneDeep(require('../base-client'));

Client.API = require('./api');
Client.Common = require('./common');
Client.log = require('./log');
Client.PayPro = require('./paypro');
Client.Verifier = require('./verifier');

module.exports = Client;
