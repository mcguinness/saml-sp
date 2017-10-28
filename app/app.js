'use strict';

const express             = require('express'),
      _                   = require('underscore'),
      path                = require('path'),
      fs                  = require('fs'),
      hbs                 = require('hbs'),
      logger              = require('morgan'),
      cookieParser        = require('cookie-parser'),
      bodyParser          = require('body-parser'),
      session             = require('express-session'),
      flash               = require('connect-flash'),
      passport            = require('passport'),
      SamlStrategy        = require('passport-wsfed-saml2').Strategy,
      SamlpLogout         = require('samlp-logout');

const AUTHN_REQUEST_TEMPLATE = _.template(
  fs.readFileSync(path.join(__dirname, '/templates/authnrequest.tpl'), 'utf8')
);
const METADATA_TEMPLATE = _.template(
  fs.readFileSync(path.join(__dirname, '/templates/metadata.tpl'), 'utf8')
);
const SLO_URL = '/saml/slo';


function getPath(path) {
  if (path) {
    return path.startsWith('/') ? path : '/' + path;
  }
}

function getReqUrl(req, path) {
  if (req) {
    return req.protocol + '://' + (req.get('x-forwarded-host') || req.get('host')) + getPath(path || req.originalUrl);
  }
};

function removeHeaders(cert) {
  const pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert);
  if (pem && pem.length > 0) {
    return pem[2].replace(/[\n|\r\n]/g, '');
  }
  return null;
};


module.exports.create = (config) => {
  const app = express();

  config = _.extend({}, config, {
    requestAcsUrl: config.acsUrls[0],
    failureRedirect: '/error',
    failureFlash: true,

    // can't use arrow functions due to lexical scoping

    getMetadataParams: function(req) {
      return {
        entityID: this.audience,
        cert: removeHeaders(this.spCert),
        acsUrls: this.acsUrls.map(url => getReqUrl(req, url)),
        sloUrl: getReqUrl(req, SLO_URL),
        nameIDFormat: this.nameIDFormat
      }
    },

    getAuthnRequestParams: function(forceAuthn, relayState, acsUrl) {
      const params = {
        protocol:             this.protocol,
        realm:                this.audience,
        callback:             acsUrl,
        protocolBinding:      this.idpSsoBinding,
        identityProviderUrl:  this.idpSsoUrl,
        providerName:         this.providerName,
        forceAuthn:           forceAuthn,
        authnContext:         this.authnContextClassRef,
        requestContext: {
          NameIDFormat: this.nameIDFormat
        },
        requestTemplate:      AUTHN_REQUEST_TEMPLATE({
          ForceAuthn: forceAuthn,
          NameIDFormat: this.requestNameIDFormat,
          AuthnContext: this.requestAuthnContext,
        }),
        signatureAlgorithm:   this.signatureAlgorithm,
        digestAlgorithm:      this.digestAlgorithm,
        deflate:              this.deflate,
        RelayState:           relayState || this.defaultRelayState,
        failureRedirect:      this.failureRedirect,
        failureFlash:         this.failureFlash
      }

      if (this.signAuthnRequests) {
        params.signingKey = {
          cert: this.spCert,
          key: this.spKey
        }
      }
      return params;
    },

    getSamlResponseParams: function(destinationUrl) {
      return {
        protocol: this.protocol,
        thumbprint: this.idpThumbprint,
        cert: this.idpCert,
        realm: this.audience,
        recipientUrl: destinationUrl,
        destinationUrl: destinationUrl,
        decryptionKey: this.spKey,
        checkResponseID: true,
        checkDestination: true,
        checkInResponseTo: true,
        checkExpiration: true,
        checkAudience: true,
        checkNameQualifier: true,
        checkSPNameQualifier: true,
        failureRedirect: this.failureRedirect,
        failureFlash: this.failureFlash
      }
    },

    getLogoutParams: function() {
      return {
        issuer: this.audience,
        protocolBinding: this.idpSloBinding,
        deflate: this.deflate,
        identityProviderUrl: this.idpSloUrl,
        identityProviderSigningCert: this.idpCert,
        key: this.spKey,
        cert: this.spCert
      }
    }

  });


  /**
   * Middleware.
   */

  // environment
  app.set('views', path.join(__dirname, 'views'));

  // view engine
  app.set('view engine', 'hbs');
  app.set('view options', { layout: 'layout' });

  hbs.registerHelper('ifArray', function(item, options) {
    if(Array.isArray(item)) {
      return options.fn(this);
    } else {
      return options.inverse(this);
    }
  });

  hbs.registerHelper('select', function(selected, options) {
    return options.fn(this).replace(
      new RegExp(' value=\"' + selected + '\"'),
      '$& selected="selected"');
  });


  // middleware
  app.use(logger(':date> :method :url - {:referrer} => :status (:response-time ms)'));
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(session({
    secret: 'You tell me what you want and I\'ll tell you what you get',
    resave: false,
    saveUninitialized: true}));
  app.use(flash());
  app.use(passport.initialize());
  app.use(passport.session());

  const strategy = new SamlStrategy(config.getSamlResponseParams(),
    (profile, done) => {
      console.log();
      console.log('Assertion => ' + JSON.stringify(profile, null, '\t'));
      console.log();
      return done(null, {
        issuer: profile.issuer,
        subject: {
          name: profile.nameIdAttributes.value,
          format: profile.nameIdAttributes.Format
        },
        authnContext: {
          sessionIndex: profile.sessionIndex,
          authnMethod: profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod']
        },
        claims: _.chain(profile)
                  .omit('issuer', 'sessionIndex', 'nameIdAttributes',
                    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
                    'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod')
                  .value()
      });
    }
  );
  strategy.logout = SamlpLogout(config.getLogoutParams());
  passport.use(strategy);


  // passport
  passport.serializeUser(function(user, done) {
    done(null, user);
  });

  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

  /**
   * Routes
   */

  app.get('/login', function (req, res, next) {
    console.log('query', req.query);
    const params = config.getAuthnRequestParams(
      req.query.forceauthn === '' || req.query.forceAuthn === '' || req.query.forceauthn || req.query.forceAuthn,
      req.session.returnTo,
      req.query.acsUrl ?
        getReqUrl(req, req.query.acsUrl) :
        getReqUrl(req, config.requestAcsUrl)
    );

    console.log('Generating AuthnRequest with Params ', params);
    // Set Session State for SAMLResponse
    req.session.authnRequest = params;
    delete req.session.returnTo;

    passport.authenticate('wsfed-saml2', params)(req, res, next);
  });

  config.acsUrls.forEach(function(acsUrl) {
    app.post(getPath(acsUrl),
      function (req, res, next) {
        if (req.method === 'POST' && req.body && req.body.SAMLResponse) {
          const respCtx = {
            RelayState: req.body.RelayState,
            Url: getReqUrl(req),
            Xml: Buffer.from(req.body.SAMLResponse, 'base64').toString('utf8')
          }
          req.session.authnResponse = respCtx;
          console.log('Received SAMLResponse message on ACS URL %s', respCtx.Url)
          console.log(respCtx.Xml);

          const params = config.getSamlResponseParams(respCtx.Url);
          console.log('Validating SAMLResponse message with Params ', params);
          _.extend(strategy.options, params);
          passport.authenticate('wsfed-saml2', params)(req, res, next);
        } else {
          res.redirect('/login');
        }
      },
      function(req, res, next) {
        res.redirect('/profile');
      });
  });

  app.post(SLO_URL,
    function (req, res, next) {
      if (req.isAuthenticated()) {
        const username = req.user.subject.name;
        console.log('Attempting to logout user %s via SAML SLO', username);
        strategy.logout(req, res, next);
        console.log('User %s successfully logged out', username);
      }
    },
    function(req, res) {
      res.render('logout');
    }
  );

  app.get(['/', '/profile'], function(req, res) {
      if(req.isAuthenticated()){
        res.render('profile', {
          request: req.session.authnRequest,
          response: req.session.authnResponse,
          profile: req.user
        });
      } else {
        res.redirect('/login');
      }
  });

  app.get('/logout', function (req, res, next) {
    if (req.isAuthenticated()) {
      if (_.isString(config.idpSloUrl)) {
        console.log("Sending SLO request for user %s", req.user.subject.name);
        req.samlSessionIndex = req.user.authnContext.sessionIndex;
        req.samlNameID = {
          value: req.user.subject.name,
          Format: req.user.subject.format
        };
        strategy.logout(req, res, next);
      } else {
        console.log('User %s successfully logged out', req.user.subject.name);
        req.session.destroy();
        res.render('logout');
      }
    } else {
      res.render('logout');
    }
  });

  app.get('/metadata', function(req, res, next) {
    const xml = METADATA_TEMPLATE(config.getMetadataParams(req));
    console.log(xml);
    res.set('Content-Type', 'text/xml');
    res.send(xml);
  });

  app.get('/settings', function(req, res, next) {
    res.render('settings', {
      config: config
    });
  });

  app.post('/settings', function(req, res, next) {
    Object.keys(req.body).forEach(function(key) {
      switch(req.body[key].toLowerCase()){
        case 'true': case 'yes': case '1':
          config[key] = true;
          break;
        case 'false': case 'no': case '0':
          config[key] = false;
          break;
        default:
          config[key] = req.body[key];
          break;
      }

      if (req.body[key].match(/^\d+$/)) {
        config[key] = parseInt(req.body[key], '10');
      }
    });

    console.log('Updated SP Configuration => \n', config);
    res.redirect('/');
  });

  app.get('/error', function(req, res) {
    const errors = req.flash('error');
    console.log(errors);
    res.render('error', {
      message: errors.join('<br>')
    });
  });

  // catch 404 and forward as relay state
  app.use(function(req, res) {
    if (!req.isAuthenticated()) {
      req.session.returnTo = req.originalUrl;
      res.redirect('/login');
    } else {
      res.redirect('/profile');
    }
  });

  // development error handler
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: err.status === 404 ? null : err
    });
  });

  return app;
}
