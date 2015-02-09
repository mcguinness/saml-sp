var passport = require('passport'),
    util     = require('util'),
    http     = require('http'),
    xml2js   = require('xml2js'),
    SAML     = require('saml-lib');

function SamlStrategy (options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error('SAML authentication strategy requires a verify function');
  }

  this.name = 'saml';

  passport.Strategy.call(this);

  this._verify = verify;
  this._saml = new SAML(options);
  this._passReqToCallback = !!options.passReqToCallback;
}

util.inherits(SamlStrategy, passport.Strategy);

SamlStrategy.prototype.authenticate = function (req, options) {
  var self = this;

  options.samlFallback = options.samlFallback || 'login-request';

  function validateCallback(err, profile, loggedOut) {
      if (err) {
        return self.error(err);
      }

      if (loggedOut) {
        req.logout();
        if (profile) {
          req.samlLogoutRequest = profile;
          return self._saml.getLogoutResponseUrl(req, redirectIfSuccess);
        }
        return self.pass();
      }

      var verified = function (err, user, info) {
        if (err) {
          return self.error(err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      };

      if (self._passReqToCallback) {
        self._verify(req, profile, verified);
      } else {
        self._verify(profile, verified);
      }
  }

  function redirectIfSuccess(err, url) {
    if (err) {
      self.error(err);
    } else {
      self.redirect(url);
    }
  }

  if (req.body && req.body.SAMLResponse) {
      this._saml.validatePostResponse(req.body, validateCallback);
  } else if (req.body && req.body.SAMLRequest) {
      this._saml.validatePostRequest(req.body, validateCallback);
  } else {
    var operation = {
      'login-request': 'getAuthorizeUrl',
      'logout-request': 'getLogoutUrl'
    }[options.samlFallback];
    if (!operation) {
      return self.fail();
    }
    this._saml[operation](req, redirectIfSuccess);
  }
};

SamlStrategy.prototype.logout = function(req, callback) {
  this._saml.getLogoutUrl(req, callback);
};

SamlStrategy.prototype.generateServiceProviderMetadata = function( decryptionCert ) {
  return this._saml.generateServiceProviderMetadata( decryptionCert );
};

SamlStrategy.parseIdentityProviderMetadata = function(url, callback) {

  if (!callback) {
    throw new Error('Callback is required for metadata results');
  }

  http.get(url, function (response) {
    var xml = '';

    response.on('data', function (chunk) {
        xml += chunk;
    });
    response.on('end', function() {

      var result = { sso: {}, slo: {} },
          nameIds = [],
          ssoEl;
        
      var parserConfig = {
        explicitRoot: true,
        explicitCharkey: true,
        tagNameProcessors: [xml2js.processors.stripPrefix]
      };
      var parser = new xml2js.Parser(parserConfig);

      parser.parseString(xml, function (err, metadata) {

        var getBindingLocation = function(serviceEl, bindingUri) {
         var location;
         if (serviceEl && serviceEl.length > 0) {
            serviceEl.forEach(function(element, index, array) {
              if (element.$.Binding.toLowerCase() === bindingUri) {
                location = element.$.Location;
              }
            });
          }
          return location;
        };

        if (err) {
          return callback(err, null);
        }

        if (metadata.EntityDescriptor) {
          result.issuer =  metadata.EntityDescriptor.$.entityID

          if (metadata.EntityDescriptor.IDPSSODescriptor && metadata.EntityDescriptor.IDPSSODescriptor.length === 1) {

            ssoEl = metadata.EntityDescriptor.IDPSSODescriptor[0];
            result.signRequest = ssoEl.$.WantAuthnRequestsSigned;

            if (ssoEl.KeyDescriptor && ssoEl.KeyDescriptor.length > 0) {
              for (var i=0; i<ssoEl.KeyDescriptor.length; i++) {       
                if (ssoEl.KeyDescriptor[i].$.use && 
                  ssoEl.KeyDescriptor[i].$.use.toLowerCase() !== 'signing' &&
                  ssoEl.KeyDescriptor[i].KeyInfo && 
                  ssoEl.KeyDescriptor[i].KeyInfo.length === 1, 
                  ssoEl.KeyDescriptor[i].KeyInfo[0].X509Data && 
                  ssoEl.KeyDescriptor[i].KeyInfo[0].X509Data.length === 1,
                  ssoEl.KeyDescriptor[i].KeyInfo[0].X509Data[0].X509Certificate &&
                  ssoEl.KeyDescriptor[i].KeyInfo[0].X509Data[0].X509Certificate.length === 1) {

                  result.signingKey = ssoEl.KeyDescriptor[i].KeyInfo[0].X509Data[0].X509Certificate[0]._;
                }
              }
            }

            if (ssoEl.NameIDFormat && ssoEl.NameIDFormat.length > 0) {
              
              ssoEl.NameIDFormat.forEach(function(element, index, array) {
                if (element._) {
                  nameIds.push(element._);
                }
              });

              if (nameIds.indexOf('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress') >= 0) {
                result.nameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
              } else if (nameIds.indexOf('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified') >= 0) {
                result.nameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
              } else if (nameIds.indexOf('urn:oasis:names:tc:SAML:2.0:nameid-format:transient') >= 0) {
                result.nameIDFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
              } else if (nameIds.indexOf('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent') >= 0) {
                result.nameIDFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
              } else if (nameIds.indexOf('urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos') >= 0) {
                result.nameIDFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos';
              } else if (nameIds.indexOf('urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName') >= 0) {
                result.nameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName';
              }
            }

            result.sso.redirectUrl = getBindingLocation(ssoEl.SingleSignOnService, 'urn:oasis:names:tc:saml:2.0:bindings:http-redirect');
            result.sso.postUrl = getBindingLocation(ssoEl.SingleSignOnService, 'urn:oasis:names:tc:saml:2.0:bindings:http-post');

            result.slo.redirectUrl = getBindingLocation(ssoEl.SingleLogoutService, 'urn:oasis:names:tc:saml:2.0:bindings:http-redirect');
            result.slo.postUrl = getBindingLocation(ssoEl.SingleLogoutService, 'urn:oasis:names:tc:saml:2.0:bindings:http-post');
          }
        }
      });

      callback(null, result);
    })
  }).on('error', function (e) {
      console.log('problem with metadata request: ' + e.message);
      callback(e, null);
  });
}



module.exports = SamlStrategy;