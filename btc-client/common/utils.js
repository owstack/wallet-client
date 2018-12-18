'use strict';

var cLib = require('../cLib');

var BaseWalletClient = require('../../base-client');
var BaseUtils = BaseWalletClient.Common.Utils;

var Unit = cLib.Unit;

var context = {
	Unit: Unit
};

class CUtils extends BaseUtils {
	constructor() {
	  super(context);
	}
};

module.exports = CUtils;
