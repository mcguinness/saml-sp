'use strict';

const _                   = require('underscore'),
      os                  = require('os'),
      fs                  = require('fs'),
      http                = require('http'),
      https               = require('https'),
      path                = require('path'),
      yargs               = require('yargs'),
      SamlMetadata        = require('./saml-metadata'),
      App                 = require('../app/app');

/**
 * Globals
 */

const KEY_CERT_HELP_TEXT = "Please generate a key-pair for the SP using the following openssl command:\n" +
      "\topenssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Service Provider' -keyout ./config/sp-key.pem -out ./config/sp-cert.pem -days 7300";

const pemTypes = {
  certificate: /-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/,
  privateKey: /-----BEGIN RSA PRIVATE KEY-----\n[^-]*\n-----END RSA PRIVATE KEY-----/,
  publicKey: /-----BEGIN PUBLIC KEY-----\n[^-]*\n-----END PUBLIC KEY-----/,
};

function matchesCertType(value, type) {
  // console.info(`Testing ${pemTypes[type].toString()} against "${value}"`);
  // console.info(`result: ${pemTypes[type] && pemTypes[type].test(value)}`);
  return pemTypes[type] && pemTypes[type].test(value);
}

function bufferFromString(value) {
  if (Buffer.hasOwnProperty('from')) {
    // node 6+
    return Buffer.from(value);
  } else {
    return new Buffer(value);
  }
}

function resolveFilePath(filePath) {
  var possiblePath;
  console.log('resolving path %s', filePath);
  if (fs.existsSync(filePath)) {
    return filePath;
  }
  if (filePath.slice(0, 2) === '~/') {
    possiblePath = path.resolve(process.env.HOME, filePath.slice(2));
    if (fs.existsSync(possiblePath)) {
      return possiblePath;
    } else {
      // for ~/ paths, don't try to resolve further
      return filePath;
    }
  }
  ['.', __dirname].forEach(function (base) {
    possiblePath = path.resolve(base, filePath);
    if (fs.existsSync(possiblePath)) {
      return possiblePath;
    }
  });
  return null;
}

function makeCertFileCoercer(type, description, helpText) {
  return function certFileCoercer(value) {
    if (matchesCertType(value, type)) {
      return value;
    }

    const filePath = resolveFilePath(value);
    if (filePath) {
      return fs.readFileSync(filePath, 'utf8')
    }
    throw new Error(
      'Invalid ' + description + ', not a valid cert/key or file path' +
      (helpText ? '\n' + helpText : '')
    )
  };
}

function processArgs(options) {
  var baseArgv;

  if (options) {
    baseArgv = yargs.config(options);
  } else {
    baseArgv = yargs.config('settings', function(settingsPathArg) {
      const settingsPath = resolveFilePath(settingsPathArg);
      return JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    });
  }
  return baseArgv
    .usage('\nSimple SAML SP for SAML 2.0 WebSSO Profile\n\n' +
      'Usage:  $0 <options>', {
      port: {
        alias: 'p',
        description: 'Web Server listener port',
        required: true,
        number: true,
        default: 7070
      },
      protocol: {
        description: 'Federation Protocol',
        required: true,
        string: true,
        default: 'samlp'
      },
      idpIssuer: {
        alias: 'iss',
        description: 'IdP Issuer URI',
        required: false,
        string: true,
        default: 'urn:example:idp'
      },
      idpSsoUrl: {
        description: 'IdP Single Sign-On Service URL (SSO URL)',
        required: false,
        string: true
      },
      idpSsoBinding: {
        description: 'IdP Single Sign-On AuthnRequest Binding',
        required: true,
        string: true,
        default: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
      },
      idpSloUrl: {
        description: 'IdP Single Logout Service URL (SLO URL)',
        required: false,
        string: true
      },
      idpSloBinding: {
        description: 'IdP Single Logout Request Binding',
        required: true,
        string: true,
        default: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
      },
      idpCert: {
        description: 'IdP Public Key Signing Certificate (PEM)',
        required: false,
        string: true,
        coerce: makeCertFileCoercer('certificate', 'IdP Public Key Signing Certificate (PEM)', KEY_CERT_HELP_TEXT)
      },
      idpThumbprint: {
        description: 'IdP Public Key Signing Certificate SHA1 Thumbprint',
        required: false,
        string: true,
        coerce: (value) => {
          return value ? value.replace(/:/g, '') : value
        }
      },
      idpMetaUrl: {
        description: 'IdP SAML Metadata URL',
        required: false,
        string: true
      },
      audience: {
        alias: 'aud',
        description: 'SP Audience URI',
        required: false,
        string: true,
        default: 'urn:example:sp'
      },
      providerName: {
        description: 'SP Provider Name',
        required: false,
        string: true,
        default: 'Simple SAML Service Provider'
      },
      acsUrls: {
        description: 'SP Assertion Consumer Service (ACS) URLs (Relative URL)',
        required: true,
        array: true,
        default: ['/saml/sso']
      },
      signAuthnRequests: {
        alias: 'signed',
        description: 'Sign AuthnRequest Messages',
        required: true,
        boolean: true,
        default: true,
      },
      signatureAlgorithm: {
        description: 'Signature Algorithm',
        required: false,
        string: true,
        default: 'rsa-sha256'
      },
      digestAlgorithm: {
        description: 'Digest Algorithm',
        required: false,
        string: true,
        default: 'sha256'
      },
      requestNameIDFormat : {
        description: 'Request Subject NameID Format',
        required: false,
        boolean: true,
        default: true
      },
      validateNameIDFormat : {
        description: 'Validate format of Assertion Subject NameID',
        required: false,
        boolean: true,
        default: true
      },
      nameIDFormat : {
        alias: 'nameid',
        description: 'Assertion Subject NameID Format',
        required: false,
        string: true,
        default: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
      },
      requestAuthnContext : {
        description: 'Request Authentication Context',
        required: false,
        boolean: true,
        default: true
      },
      authnContextClassRef : {
        alias: 'acr',
        description: 'Authentication Context Class Reference',
        required: false,
        string: true,
        default: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
      },
      spCert: {
        description: 'SP Public Key Signature Certificate (PEM)',
        string: true,
        required: false,
        default: path.resolve(__dirname, '../config/sp-cert.pem'),
        coerce: makeCertFileCoercer('certificate', 'SP Signing Public Key Certificate (PEM)', KEY_CERT_HELP_TEXT)
      },
      spKey: {
        description: 'SP Private Key Signature Certificate (PEM)',
        string: true,
        required: false,
        default: path.resolve(__dirname, '../config/sp-key.pem'),
        coerce: makeCertFileCoercer('privateKey', 'SP Signing Private Key (PEM)', KEY_CERT_HELP_TEXT)
      },
      httpsPrivateKey: {
        description: 'Web Server TLS/SSL Private Key (PEM)',
        required: false,
        string: true,
        coerce: makeCertFileCoercer('privateKey', 'Web Server TLS/SSL Private Key (PEM)', KEY_CERT_HELP_TEXT)
      },
      httpsCert: {
        description: 'Web Server TLS/SSL Certificate (PEM)',
        required: false,
        string: true,
        coerce: makeCertFileCoercer('certificate', 'Web Server TLS/SSL Public Key Certificate (PEM)', KEY_CERT_HELP_TEXT)
      },
      https: {
        description: 'Enables HTTPS Listener (requires httpsPrivateKey and httpsCert)',
        required: false,
        boolean: true,
        default: false
      },
      relayState: {
        alias: 'rs',
        description: 'Default Relay State',
        required: false,
        string: true
      }
    })
    .example('  $0 --idpMetaUrl https://example.okta.com/app/exknnoOGPcwWSnKUK0g3/sso/saml/metadata',
      'Dynamic IdP configuration with SAML Metadata')
    .example('  $0 --idpIssuer http://www.okta.com/exknnoOGPcwWSnKUK0g3 --idpSsoUrl https://example.okta.com/app/example_saml_2/exk7s3gpHWyQaKyFx0g4/sso/saml --idpCert ./idp-cert.pem',
      'Static IdP configuration with Public Key')
    .example('  $0 --idpIssuer http://www.okta.com/exknnoOGPcwWSnKUK0g3 --idpSsoUrl https://example.okta.com/app/example_saml_2/exk7s3gpHWyQaKyFx0g4/sso/saml --idpThumbprint ./idp-cert.pem',
      'Static IdP configuration with Thumbprint')
    .check((argv, aliases) => {
      if (argv.https ) {
        return (argv.httpsPrivateKey && argv.httpsCert) ?
          true :
          'Certificate and Private Key is required for HTTPS';
      }
      return true;
    })
    .check((argv, aliases) => {
      if (!_.isString(argv.idpMetaUrl)) {
        if (!_.isString(argv.idpSsoUrl) || argv.idpSsoUrl === '') {
          return 'IdP SSO Assertion Consumer URL (idpSsoUrl) is required when SAML metadata is not specified';
        }
        if (!_.isString(argv.idpCert) && !_.isString(argv.idpThumbprint)) {
          return ' IdP Signing Certificate (idpCert) or IdP Signing Key Thumbprint (idpThumbprint) is required when SAML metadata is not specified';
        }
      }
      return true;
    })
    .help()
    .wrap(yargs.terminalWidth())
}

function _runServer(argv) {
  SamlMetadata.fetch(argv.idpMetaUrl)
    .then((metadata) => {
      if (metadata) {
        if (_.isString(metadata.sso.redirectUrl)) {
          argv.idpSsoUrl = metadata.sso.redirectUrl;
          argv.idpSsoBinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
        } else if (_.isString(metadata.sso.postUrl)) {
          argv.idpSsoUrl = metadata.sso.postUrl;
          argv.idpSsoBinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        }

        if (_.isString(metadata.slo.redirectUrl)) {
          argv.idpSloUrl = metadata.slo.redirectUrl;
          argv.idpSloBinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
        } else if (_.isString(metadata.slo.postUrl)) {
          argv.idpSloUrl = metadata.slo.postUrl;
          argv.idpSloBinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        }

        if (metadata.signRequest) {
          argv.signAuthnRequests = metadata.signRequest;
        }

        if (_.isString(metadata.signingKey)) {
          argv.idpCert = metadata.signingKey;
        }
      }
    })
    .then(() => {

      console.log();
      console.log('[SAML Service Provider Configuration]\n', argv)
      console.log();

      const app = App.create(argv);
      const httpServer = argv.https ?
        https.createServer({ key: argv.httpsPrivateKey, cert: argv.httpsCert }, app) :
        http.createServer(app);

      console.log();
      console.log('starting server...');
      httpServer.listen(argv.port, function() {
        const scheme   = argv.https ? 'https' : 'http',
              address  = httpServer.address(),
              hostname = os.hostname(),
              baseUrl  = address.address === '0.0.0.0' ?
                scheme + '://' + hostname + ':' + address.port :
                scheme + '://localhost:' + address.port;

        console.log('\n\t' + baseUrl);
        console.log();
        console.log('IdP Issuer URI:\n\t' + argv.idpIssuer);
        console.log('IdP SSO ACS URL:\n\t' + argv.idpSsoUrl);
        console.log('IdP SLO URL:\n\t' + argv.idpSloUrl);
        console.log();
        console.log('SP Issuer URI:\n\t' + argv.audience);
        console.log('SP Audience URI:\n\t' + argv.audience);
        console.log('SP NameID Format:\n\t' + argv.nameIDFormat);
        console.log('SP ACS Binding:\n\turn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
        console.log('SP ACS URL:');
        argv.acsUrls.forEach(function(acsUrl) {
          console.log('\t' + acsUrl);
        });
        console.log('SP Default Relay State:\n\t' + argv.defaultRelayState);
        console.log();
      });
    })
    .catch((err) => {
      console.log(err);
    })
}

module.exports = {
  runServer: (options) => {
    const args = processArgs(options);
    _runServer(args.parse([]));
  },
  main: function() {
    const args = processArgs();
    _runServer(args.argv);
  },
};

if (require.main === module) {
  module.exports.main();
}
