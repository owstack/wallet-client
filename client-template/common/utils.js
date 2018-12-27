'use strict';

var cLib = require('../cLib');
var owsCommon = require('@owstack/ows-common');
var Context = owsCommon.util.Context;

var BaseWalletClient = require('../../base-client');
var BaseUtils = BaseWalletClient.Common.Utils;

var Unit = cLib.Unit;

var context = new Context({
	Unit: Unit
});

class CUtils extends BaseUtils {
	constructor() {
	  super(context);
	}
};

module.exports = CUtils;
