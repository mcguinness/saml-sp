'use strict';

const util     = require('util'),
      request  = require("request"),
      xml2js   = require('xml2js');

function getBindingLocation(serviceEl, bindingUri) {
  var location;
  if (serviceEl && serviceEl.length > 0) {
    serviceEl.forEach((element, index, array) => {
      if (element.$.Binding.toLowerCase() === bindingUri) {
        location = element.$.Location;
      }
    });
  }
  return location;
};

function fetch(url) {

  return new Promise((resolve, reject) => {
    const metadata = { sso: {}, slo: {} };

    if (typeof url === 'undefined' || url === null) {
      return resolve(metadata);
    }

    console.log('downloading SAML IdP metadata from ' + url)
    request.get(url, (err, resp, body) => {
      if (err) {
        console.log('unable to fetch metadata: ' + err.message);
        return reject(err);
      };

      console.log();
      console.log(body);
      console.log();

      const parserConfig  = {
                              explicitRoot: true,
                              explicitCharkey: true,
                              tagNameProcessors: [xml2js.processors.stripPrefix]
                            },
            parser        = new xml2js.Parser(parserConfig),
            nameIds       = [];

      parser.parseString(body, (err, doc) => {
        if (err) {
          return reject(err);
        }

        if (doc.EntityDescriptor) {
          metadata.issuer = doc.EntityDescriptor.$.entityID

          if (doc.EntityDescriptor.IDPSSODescriptor && doc.EntityDescriptor.IDPSSODescriptor.length === 1) {

            let ssoEl = doc.EntityDescriptor.IDPSSODescriptor[0];
            metadata.signRequest = ssoEl.$.WantAuthnRequestsSigned;

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

                  metadata.signingKey = ssoEl.KeyDescriptor[i].KeyInfo[0].X509Data[0].X509Certificate[0]._;
                }
              }
            }

            if (ssoEl.NameIDFormat && ssoEl.NameIDFormat.length > 0) {

              ssoEl.NameIDFormat.forEach((element, index, array) => {
                if (element._) {
                  nameIds.push(element._);
                }
              });

              if (nameIds.indexOf('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress') >= 0) {
                metadata.nameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
              } else if (nameIds.indexOf('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified') >= 0) {
                metadata.nameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
              } else if (nameIds.indexOf('urn:oasis:names:tc:SAML:2.0:nameid-format:transient') >= 0) {
                metadata.nameIDFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
              } else if (nameIds.indexOf('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent') >= 0) {
                metadata.nameIDFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
              } else if (nameIds.indexOf('urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos') >= 0) {
                metadata.nameIDFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos';
              } else if (nameIds.indexOf('urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName') >= 0) {
                metadata.nameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName';
              }
            }

            metadata.sso.redirectUrl = getBindingLocation(ssoEl.SingleSignOnService, 'urn:oasis:names:tc:saml:2.0:bindings:http-redirect');
            metadata.sso.postUrl = getBindingLocation(ssoEl.SingleSignOnService, 'urn:oasis:names:tc:saml:2.0:bindings:http-post');

            metadata.slo.redirectUrl = getBindingLocation(ssoEl.SingleLogoutService, 'urn:oasis:names:tc:saml:2.0:bindings:http-redirect');
            metadata.slo.postUrl = getBindingLocation(ssoEl.SingleLogoutService, 'urn:oasis:names:tc:saml:2.0:bindings:http-post');
          }
        }
      });

      return resolve(metadata);
    });
  });
}

module.exports = {
  fetch: fetch
};
