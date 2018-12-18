'use strict';

var cLib = require('./cLib');

var BaseWalletClient = require('../base-client');
var BaseLog = BaseWalletClient.Log;

var Networks = cLib.Networks;

module.exports = new BaseLog(Networks.livenet.name + ' wallet client');
