var util     = require('util'),
    request  = require("request"),
    xml2js   = require('xml2js');


function fetch(url, callback) {

  if (!callback) {
    throw new Error('Callback is required for metadata results');
  }

  request.get(url, function (err, resp, body) {
    if (err) {
      console.log('problem with metadata request: ' + err.message);
      return callback(err)
    };

    var result = { sso: {}, slo: {} },
        nameIds = [],
        ssoEl;

    var parserConfig = {
      explicitRoot: true,
      explicitCharkey: true,
      tagNameProcessors: [xml2js.processors.stripPrefix]
    };
    var parser = new xml2js.Parser(parserConfig);

    parser.parseString(body, function (err, metadata) {

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
        result.issuer = metadata.EntityDescriptor.$.entityID

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
  });
}

module.exports = {
  fetch: fetch
};
