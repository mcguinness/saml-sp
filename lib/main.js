'use strict';

const _                   = require('underscore'),
      os                  = require('os'),
      fs                  = require('fs'),
      http                = require('http'),
      https               = require('https'),
      path                = require('path'),
      yargs               = require('yargs'),
      IdPMetadata        = require('./idp-metadata'),
      App                 = require('../app/app');

/**
 * Globals
 */

const NAMEID_FORMAT_PREFERENCE = [
  'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName'
]

const BINDINGS = {
  REDIRECT: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
  POST: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
}

const KEY_CERT_HELP_TEXT = "Please generate a key-pair for the SP using the following openssl command:\n" +
      "\topenssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Service Provider' -keyout ./config/sp-key.pem -out ./config/sp-cert.pem -days 7300";

const PEM_TYPES = {
  certificate: /-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/,
  privateKey: /-----BEGIN RSA PRIVATE KEY-----\n[^-]*\n-----END RSA PRIVATE KEY-----/,
  publicKey: /-----BEGIN PUBLIC KEY-----\n[^-]*\n-----END PUBLIC KEY-----/,
};

function matchesCertType(value, type) {
  // console.info(`Testing ${PEM_TYPES[type].toString()} against "${value}"`);
  // console.info(`result: ${PEM_TYPES[type] && PEM_TYPES[type].test(value)}`);
  return PEM_TYPES[type] && PEM_TYPES[type].test(value);
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

function certToPEM(cert) {
  if (cert) {
    if (/-----BEGIN CERTIFICATE-----/.test(cert)) {
      return cert;
    }

    cert = cert.match(/.{1,64}/g).join('\n');
    cert = "-----BEGIN CERTIFICATE-----\n" + cert;
    cert = cert + "\n-----END CERTIFICATE-----\n";
    return cert;
  }
}

function processArgs(options) {
  var baseArgv;

  console.log();
  console.log('parsing arguments...');
  // disable auto expansion
  yargs.parserConfiguration({
    "camel-case-expansion": false
  });
  if (options) {
    baseArgv = yargs.config(options);
  } else {
    baseArgv = yargs.config('settings', function(settingsPathArg) {
      const settingsPath = resolveFilePath(settingsPathArg);
      return JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    });
  }
  return baseArgv
    .usage('\nSimple SAML Service Provider / WS-Federation Relying Party\n\n' +
      'Usage:  $0 <options>')
    .options({
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
        default: BINDINGS.REDIRECT,
        choices: [BINDINGS.REDIRECT, BINDINGS.POST]
      },
      idpSloUrl: {
        description: 'IdP Single Logout Service URL (SLO URL) (SAMLP)',
        required: false,
        string: true
      },
      idpSloBinding: {
        description: 'IdP Single Logout Request Binding (SAMLP)',
        required: true,
        string: true,
        default: BINDINGS.REDIRECT,
        choices: [BINDINGS.REDIRECT, BINDINGS.POST]
      },
      idpCert: {
        description: 'IdP Public Key Signing Certificate (PEM)',
        required: false,
        string: true,
        coerce: (value) => {
          return certToPEM(makeCertFileCoercer('certificate', 'IdP Public Key Signing Certificate (PEM)', KEY_CERT_HELP_TEXT)(value));
        }
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
        description: 'SP Audience URI / RP Realm',
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
        description: 'Sign AuthnRequest Messages (SAMLP)',
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
        description: 'Request Subject NameID Format (SAMLP)',
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
        description: 'Request Authentication Context (SAMLP)',
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
        description: 'SP/RP Public Key Signature & Encryption Certificate (PEM)',
        string: true,
        required: false,
        default: path.resolve(__dirname, '../config/sp-cert.pem'),
        coerce: makeCertFileCoercer('certificate', 'SP Signing Public Key Certificate (PEM)', KEY_CERT_HELP_TEXT)
      },
      spKey: {
        description: 'SP/RP Private Key Signature & Decryption Certificate(PEM)',
        string: true,
        required: false,
        default: path.resolve(__dirname, '../config/sp-key.pem'),
        coerce: makeCertFileCoercer('privateKey', 'SP Signing Private Key (PEM)', KEY_CERT_HELP_TEXT)
      },
      spSsoBinding: {
        description: 'SP SAMLP Assertion Consumer Service (ACS) Binding',
        string: true,
        required: true,
        default: BINDINGS.POST,
        choices: [BINDINGS.POST]
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
          return 'IdP SSO Assertion Consumer URL (idpSsoUrl) is required when IdP metadata is not specified';
        }
        if (!_.isString(argv.idpCert) && !_.isString(argv.idpThumbprint)) {
          return ' IdP Signing Certificate (idpCert) or IdP Signing Key Thumbprint (idpThumbprint) is required when IdP metadata is not specified';
        }
        // convert cert to PEM
        if (argv.idpCert) {
          argv.idpCertPEM = certToPEM(argv.idpCert)
        }
      }
      return true;
    })
    .help()
    .wrap(yargs.terminalWidth())
}

function _runServer(argv) {
  IdPMetadata.fetch(argv.idpMetaUrl)
    .then((metadata) => {
      if (metadata.protocol) {
        argv.protocol = metadata.protocol;
        if (metadata.signingKeys[0]) {
          argv.idpCert = certToPEM(metadata.signingKeys[0]);
        }

        switch (metadata.protocol) {
          case 'samlp':
            switch (argv.idpSsoBinding) {
              case BINDINGS.REDIRECT:
                if (metadata.sso.redirectUrl) {
                  argv.idpSsoUrl = metadata.sso.redirectUrl;
                  break;
                } else if (metadata.sso.postUrl) {
                  argv.idpSsoUrl = metadata.sso.postUrl;
                  argv.idpSsoBinding = BINDINGS.POST
                }
                break;
              case BINDINGS.POST:
                if (metadata.sso.postUrl) {
                  argv.idpSsoUrl = metadata.sso.postUrl;
                  break;
                } else if (metadata.sso.redirectUrl) {
                  argv.idpSsoUrl = metadata.sso.redirectUrl;
                  argv.idpSsoBinding = BINDINGS.REDIRECT
                }
                break;
              default:
                break;
            }

            switch (argv.idpSloBinding) {
              case BINDINGS.REDIRECT:
                if (metadata.slo.redirectUrl) {
                  argv.idpSloUrl = metadata.slo.redirectUrl;
                  break;
                } else if (metadata.slo.postUrl) {
                  argv.idpSloUrl = metadata.slo.postUrl;
                  argv.idpSloBinding = BINDINGS.POST
                }
                break;
              case BINDINGS.POST:
                if (metadata.slo.postUrl) {
                  argv.idpSloUrl = metadata.slo.postUrl;
                  break;
                } else if (metadata.slo.redirectUrl) {
                  argv.idpSloUrl = metadata.slo.redirectUrl;
                  argv.idpSloBinding = BINDINGS.REDIRECT
                }
                break;
              default:
                break;
            }
            break;
          case 'wsfed':
            if (metadata.sso.redirectUrl) {
              argv.idpSsoUrl = metadata.sso.redirectUrl;
            }
            break;
          default:
            break;
        }
      }
    })
    .then(() => {

      console.log();
      console.log('[Configuration]\n', argv);
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

        switch (argv.protocol) {
          case 'samlp' :
            console.log();
            console.log('Protocol: ' + "SAMLP");
            console.log();
            console.log('IdP Issuer URI:\n\t' + argv.idpIssuer);
            console.log('IdP SSO ACS URL:\n\t' + argv.idpSsoUrl);
            console.log('IdP SSO Binding:\n\t' + argv.idpSsoBinding);
            console.log('IdP SLO URL:\n\t' + argv.idpSloUrl);
            console.log('IdP SLO Binding:\n\t' + argv.idpSloBinding);
            console.log();
            console.log('SP Issuer URI:\n\t' + argv.audience);
            console.log('SP Audience URI:\n\t' + argv.audience);
            console.log('SP NameID Format:\n\t' + argv.nameIDFormat);
            console.log('SP ACS Binding:\n\t' + argv.spSsoBinding);
            console.log('SP ACS URL:');
            argv.acsUrls.forEach(function(acsUrl) {
              console.log('\t' + acsUrl);
            });
            console.log('SP Default Relay State:\n\t' + argv.relayState);
            console.log();
            break;
          case 'wsfed' :
            console.log();
            console.log('Protocol: ' + "WS-Federation");
            console.log();
            console.log('IdP Issuer URI:\n\t' + argv.idpIssuer);
            console.log('IdP SSO ACS URL:\n\t' + argv.idpSsoUrl);
            console.log();
            console.log('RP Issuer URI:\n\t' + argv.audience);
            console.log('RP Audience URI:\n\t' + argv.audience);
            console.log('RP Security Token Response URL:');
            argv.acsUrls.forEach(function(acsUrl) {
              console.log('\t' + acsUrl);
            });
            console.log('RP Default Context:\n\t' + argv.relayState);
            console.log();
            break;
          default:
            throw new Error('protocol ' + argv.protocol + ' not supported!');
            break;
        }
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
