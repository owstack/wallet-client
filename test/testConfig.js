'use strict';

var config = {
  basePath: '/ws/api',
  port: 3232,
  ignoreRateLimiter: false,

  // Log levels; debug, warn, info, error
  log: {
    disable: false,
    level: 'info'
  },

  // Uncomment to make wallet-service a forking server
  // cluster: true,

  // Uncomment to set the number or process (will use the nr of availalbe CPUs by default)
  // clusterInstances: 4,

  // https: true,
  // privateKeyFile: 'private.pem',
  // certificateFile: 'cert.pem',
  ////// The following is only for certs which are not
  ////// trusted by nodejs 'https' by default
  ////// CAs like Verisign do not require this
  // CAinter1: '', // ex. 'COMODORSADomainValidationSecureServerCA.crt'
  // CAinter2: '', // ex. 'COMODORSAAddTrustCA.crt'
  // CAroot: '', // ex. 'AddTrustExternalCARoot.crt'

  storageOpts: {
    mongoDb: {
      uri: 'mongodb://localhost:27017/btcws'
    }
  },
/*
  lockOpts: {
    //  To use locker-server, uncomment this:
    lockerServer: {
      host: 'localhost',
      port: 3231
    }
  },

  messageBrokerOpts: {
    port: 3380,
    // If using a remote server.
    // messageBrokerServer: {
    //   url: 'http://remotehost:3380'
    // }
  },
*/
  // To use email notifications:
  // emailOpts: {
  //   transport: {
  //     host: 'localhost',
  //     port: 25,
  //     ignoreTLS: true,
  //   },
  //   defaultLanguage: 'en',
  //   subjectPrefix: '[Wallet Service]',
  //   from: 'wallet-service@owstack.com',
  //   templatePath: './lib/templates',
  //   publicTxUrlTemplate: {
  //     'livenet': 'https://explorer.openwalletstack.com/tx/{{txid}}',
  //     'testnet': 'https://test-explorer.openwalletstack.com/tx/{{txid}}'
  //   }
  // },

  // Sendgrid.
  // const sgMail = require('@sendgrid/mail');
  // sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  //
  // Add config:
  // mailer: sgMail,

  pushNotificationsOpts: {
    templatePath: './lib/templates',
    defaultLanguage: 'en',
    subjectPrefix: '',
    pushServerUrl: 'https://fcm.googleapis.com/fcm',
    authorizationKey: ''
  },

  fiatRateServiceOpts: {
    defaultProvider: 'BitPay',
    fetchInterval: 60 // in minutes
  },

  // Each server (by coin network) has it's own configuration. Where the same services
  // run for each coin network the url's must be unique across all coin networks.

  BTC: {
    blockchainExplorerOpts: {
      defaultProvider: 'explorer',
      explorer: {
        // Multiple servers (in priority order)
        // url: ['http://a.b.c', 'https://test-explorer.owstack.com:443'],
        livenet: {
          url: 'http://btc.livenet.explorer-api.owstack.org',
          apiPrefix: '/explorer-api'
        },
        testnet: {
          url: 'https://test-insight.bitpay.com',
          apiPrefix: '/api'
        }
      }
    }
  },

  BCH: {
    blockchainExplorerOpts: {
      defaultProvider: 'explorer',
      explorer: {
        // Multiple servers (in priority order)
        // url: ['http://a.b.c', 'https://test-explorer.owstack.com:443'],
        livenet: {
          url: 'http://bch.livenet.explorer-api.owstack.org',
          apiPrefix: '/explorer-api'
        },
        testnet: {
          url: 'https://test-insight.bitpay.com',
          apiPrefix: '/api'
        }
      }
    }
  },

  LTC: {
    blockchainExplorerOpts: {
      defaultProvider: 'explorer',
      explorer: {
        // Multiple servers (in priority order)
        // url: ['http://a.b.c', 'https://test-explorer.owstack.com:443'],
        livenet: {
          url: 'http://ltc.livenet.explorer-api.owstack.org',
          apiPrefix: '/explorer-api'
        },
        testnet: {
          url: 'https://test-insight.bitpay.com',
          apiPrefix: '/api'
        }
      }
    }
  }

};

module.exports = config;
