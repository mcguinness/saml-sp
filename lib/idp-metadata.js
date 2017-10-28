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

function getFirstCert(keyEl) {
  if (keyEl.KeyInfo &&
      keyEl.KeyInfo.length === 1,
      keyEl.KeyInfo[0].X509Data &&
      keyEl.KeyInfo[0].X509Data.length === 1,
      keyEl.KeyInfo[0].X509Data[0].X509Certificate &&
      keyEl.KeyInfo[0].X509Data[0].X509Certificate.length === 1) {

    return keyEl.KeyInfo[0].X509Data[0].X509Certificate[0]._;
  }
}

function fetch(url) {

  return new Promise((resolve, reject) => {
    const metadata = { sso: {}, slo: {}, nameIdFormats: [], signingKeys: [] };

    if (typeof url === 'undefined' || url === null) {
      return resolve(metadata);
    }

    console.log('downloading IdP metadata from ' + url)
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

      parser.parseString(body, (err, docEl) => {
        if (err) {
          return reject(err);
        }

        if (docEl.EntityDescriptor) {
          metadata.issuer = docEl.EntityDescriptor.$.entityID

          if (docEl.EntityDescriptor.IDPSSODescriptor && docEl.EntityDescriptor.IDPSSODescriptor.length === 1) {

            metadata.protocol = 'samlp';

            let ssoEl = docEl.EntityDescriptor.IDPSSODescriptor[0];
            metadata.signRequest = ssoEl.$.WantAuthnRequestsSigned;

            ssoEl.KeyDescriptor.forEach((keyEl) => {
              if (keyEl.$.use && keyEl.$.use.toLowerCase() !== 'encryption') {
                metadata.signingKeys.push(getFirstCert(keyEl));
              }
            })

            if (ssoEl.NameIDFormat) {
              ssoEl.NameIDFormat.forEach((element, index, array) => {
                if (element._) {
                  metadata.nameIdFormats.push(element._);
                }
              });
            }

            metadata.sso.redirectUrl = getBindingLocation(ssoEl.SingleSignOnService, 'urn:oasis:names:tc:saml:2.0:bindings:http-redirect');
            metadata.sso.postUrl = getBindingLocation(ssoEl.SingleSignOnService, 'urn:oasis:names:tc:saml:2.0:bindings:http-post');

            metadata.slo.redirectUrl = getBindingLocation(ssoEl.SingleLogoutService, 'urn:oasis:names:tc:saml:2.0:bindings:http-redirect');
            metadata.slo.postUrl = getBindingLocation(ssoEl.SingleLogoutService, 'urn:oasis:names:tc:saml:2.0:bindings:http-post');
          }
        }

        if (docEl.EntityDescriptor.RoleDescriptor) {
          metadata.protocol = 'wsfed';
          try {
            let roleEl = docEl.EntityDescriptor.RoleDescriptor.find((el) => {
              return el.$['xsi:type'].endsWith(':SecurityTokenServiceType');
            });
            metadata.sso.redirectUrl = roleEl.PassiveRequestorEndpoint[0].EndpointReference[0].Address[0]._

            roleEl.KeyDescriptor.forEach((keyEl) => {
              metadata.signingKeys.push(getFirstCert(keyEl));
            })
          } catch(e) {
            console.log('unable to parse RoleDescriptor metadata', e);
          }
        }
        return resolve(metadata);
      });
    });
  });
}

module.exports = {
  fetch: fetch
};
