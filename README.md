Simple SAML Service Provider for node.js.

## Installation

    npm install

## Introduction

This app provides a simple test Service Provider for [SAML 2.0 Web Browser SSO Profile](http://en.wikipedia.org/wiki/SAML_2.0#Web_Browser_SSO_Profile) 

## Usage

	`node app.js --idpSsoUrl {url} --cert {pem}`

### Example

	`node app.js --ssoUrl https://example.okta.com/app/myapp/exk7s3gpHWyQaKyFx0g4/sso/saml`