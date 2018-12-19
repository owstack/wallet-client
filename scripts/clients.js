#!/usr/bin/env node

'use strict';

var fs = require('fs-extra');

var clients = [{
  coin: 'Bitcoin Cash',
  lib: '@owstack/bch-lib',
  dir: 'lib/bch-client'
}, {
  coin: 'Bitcoin',
  lib: '@owstack/btc-lib',
  dir: 'lib/btc-client'
}, {
  coin: 'Litecoin',
  lib: '@owstack/ltc-lib',
  dir: 'lib/ltc-client'
}];

var cmd = process.argv[2];
switch (cmd) {
  case 'create': createClients(); break;
  case 'clean': cleanClients(); break;
  default: help();
};

function help() {
  console.log('usage: clients [create | clean]');
};

function createClients() {
  console.log('Creating client libraries...');
  clients.forEach(function(s) {
    var d = __dirname + '/../' + s.dir;
    copyDir(__dirname + '/../client-template', d);

    var content = '\'use strict\'; var cLib = require(\'' + s.lib + '\'); module.exports = cLib;';
    fs.writeFileSync(s.dir + '/cLib.js', content, 'utf8');

    console.log(' > ' + s.coin + ' (' + s.lib + ') at ./' + s.dir);
  });
};

function cleanClients() {
  console.log('Deleting client libraries...');
  var count = 0;
  clients.forEach(function(s) {
    var d = __dirname + '/../' + s.dir;
    if (fs.existsSync(d)) {
      fs.removeSync(d);
      count++;
      console.log(' > ' + s.coin + ' from ./' + s.dir);
    }
  });

  if (count == 0) {
    console.log(' > nothing to do');
  }
};

function copyDir(from, to) {
  if (!fs.existsSync(from)) {
    return;
  }
  if (fs.existsSync(to)) {
    fs.removeSync(to);
  }
  fs.copySync(from, to);
};
