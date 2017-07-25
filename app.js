
/**
 * Module dependencies.
 */

var express             = require('express'),
    _                   = require('underscore'),
    os                  = require('os'),
    fs                  = require('fs'),
    http                = require('http'),
    https               = require('https'),
    path                = require('path'),
    hbs                 = require('hbs'),
    logger              = require('morgan'),
    cookieParser        = require('cookie-parser'),
    bodyParser          = require('body-parser'),
    session             = require('express-session'),
    passport            = require('passport'),
    yargs               = require('yargs'),
    SamlStrategy        = require('passport-saml').Strategy,
    SamlLib             = require('passport-saml').SAML,
    SamlMetadata        = require('./SamlMetadata');

/**
 * Globals
 */

var app = express(),
    httpServer,
    strategy,
    startServer;

/**
 * Configuration
 */

const argv = yargs
  .usage('\nSimple SAML SP for SAML 2.0 WebSSO Profile', {

    port: {
      description: 'Web Server listener port',
      required: true,
      alias: 'p',
      number: true,
      default: 7070
    },
    issuer: {
      description: 'SP Issuer URI',
      required: true,
      alias: 'iss',
      string: true,
      default: 'urn:example:sp'
    },
    audience: {
      description: 'SP Audience URI',
      required: false,
      alias: 'aud',
      string: true,
      default: 'urn:example:sp'
    },
    idpSsoUrl: {
      description: 'IdP SSO Assertion Consumer URL (SSO URL)',
      string: true,
      required: false
    },
    idpSloUrl: {
      description: 'IdP Single Logout Assertion Consumer URL (SLO URL)',
      string: true,
      required: false
    },
    idpCert: {
      description: 'IdP Signing Certificate (PEM)',
      string: true,
      required: false
    },
    idpMetaUrl: {
      description: 'IdP SAML Metadata URL',
      string: true,
      required: false
    },
    spPrivateKey: {
      description: 'SP Request Signature Private Key (pem)',
      string: true,
      required: false,
      default: './server-key.pem'
    },
    idFormat : {
      description: 'Assertion Subject NameID Format',
      required: false,
      string: true,
      default: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    },
    httpsPrivateKey: {
      description: 'Web Server TLS/SSL Private Key (pem)',
      required: false,
      alias: 'key',
      string: true,
    },
    httpsCert: {
      description: 'Web Server TLS/SSL Certificate (pem)',
      required: false,
      alias: 'cert',
      string: true,
    },
    https: {
      description: 'Enables HTTPS Listener (requires httpsPrivateKey and httpsCert)',
      required: true,
      boolean: true,
      default: false
    },
      relayState: {
      description: 'Relay State',
      required: false,
      string: true,
      default: null
    }
  })
  .example('\t$0 --idpSsoUrl https://example.okta.com/app/example_saml_2/exk7s3gpHWyQaKyFx0g4/sso/saml --idpCert ./idp-cert.pem',
    'Static IdP configuration')
  .example('\t$0 --idpMetaUrl https://example.okta.com/app/exknnoOGPcwWSnKUK0g3/sso/saml/metadata',
    'Dynamic IdP configuration with SAML Metadata')
  .check(function(argv, aliases) {
    if (argv.https) {
      if (!fs.existsSync(argv.httpsPrivateKey)) {
        return 'HTTPS Private Key "' + argv.httpsPrivateKey + '" is not a valid file path';
      }
      if (!fs.existsSync(argv.httpsCert)) {
        return 'HTTPS Certificate "' + argv.httpsCert + '" is not a valid file path';
      }

      argv.httpsPrivateKey = fs.readFileSync(argv.httpsPrivateKey).toString();
      argv.httpsCert = fs.readFileSync(argv.httpsCert).toString();
    }
    return true;
  })
  .check(function(argv, aliases) {
    var cert;

    if (argv.idpMetaUrl === undefined &&
      (argv.idpSsoUrl === undefined || argv.cert === undefined)) {
      return 'IdP SAML Metadata URL (idpMetaUrl) or IdP SSO Assertion Consumer URL (idpSsoUrl) and IdP Signing Certificate (cert) is required!'
    }

    if (argv.cert) {
      if (!fs.existsSync(argv.cert)) {
        return 'IdP Signing Certificate "' + argv.cert + '" is not a valid file path';
      }
      argv.cert = fs.readFileSync(argv.cert, 'utf-8').toString();
      if (!argv.cert.match(/-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g)) {
        return 'IdP Signing Certificate "' + argv.cert + '" is not a valid PEM file';
      }
    }

    if (argv.spPrivateKey !== undefined) {
      if (!fs.existsSync(argv.spPrivateKey)) {
        return 'SP Request Signing Private Key "' + argv.spPrivateKey + '" is not a valid file path';
      }
      argv.spPrivateKey = fs.readFileSync(argv.spPrivateKey, 'utf-8').toString();
      if (!argv.spPrivateKey.match(/-----BEGIN RSA PRIVATE KEY-----([^-]*)-----END RSA PRIVATE KEY-----/g)) {
        return 'SP Request Signing Private Key "' + argv.cert + '" is not a valid PEM file';
      }
    }
    return true;
  })
  .help()
  .wrap(null)
  .argv;


/**
 * SAML Service Provider Configuration.
 */

var spOptions = {
  path:                         '/saml/sso',
  entryPoint:                   argv.idpSsoUrl,
  issuer:                       argv.issuer,
  audiencekey:                  argv.audience,
  identifierFormat:             argv.idFormat,
  acceptedClockSkewMs:          2000,
  logoutUrl:                    argv.idpSloUrl || 'N/A',
  cert:                         argv.idpCert,
  signRequest:                  true,
  signatureAlgorithm:           'sha256',
  forceAuthn:                   false,
  identifierFormat:             'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  disableRequestedAuthnContext: true,
  authnContext:                 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
  skipRequestCompression:       false,
  authnRequestBinding:          'HTTP-Redirect',
  validateInResponseTo:         true,
  privateCert:          argv.spPrivateKey,
  additionalParams:{'RelayState':argv.relayState},
  verify: function(profile, done) {
    console.log('Assertion => ' + JSON.stringify(profile, null, '\t'));
    return done(null, {
      issuer: profile.issuer._,
      sessionIndex: profile.sessionIndex,
      subject: {
        name: profile.nameID,
        format: profile.nameIDFormat
      },
      claims: _.chain(profile)
                .omit('issuer', 'nameID', 'nameIDFormat', 'sessionIndex')
                .value()
    });
  }
};

/**
 * Middleware.
 */

// environment
app.set('port', process.env.PORT || argv.port);
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
  secret: "You tell me what you want and I'll tell you what you get",
  resave: false,
  saveUninitialized: true}));
app.use(passport.initialize());
app.use(passport.session());

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


app.get("/login", function (req, res, next) {
    if (_.isString(req.session.relayState)) {
      req.query.RelayState = req.session.relayState;
    }
    //spOptions.forceAuthn = (req.query.forceauthn !== undefined); go based off the parameter on startup?
    console.log('Sending AuthnRequest with Binding [' + spOptions.authnRequestBinding + '] and ForceAuthn [' + spOptions.forceAuthn + ']');
    next();
  },
  passport.authenticate('saml', { failureRedirect: '/error', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/saml/sso',
  passport.authenticate('saml', { failureRedirect: '/error', failureFlash: true }),
  function(req, res) {
    req.session.passedRelayState = req.body.RelayState;
    res.redirect('/profile');
  }
);

app.post('/saml/sso',
  passport.authenticate('saml', { failureRedirect: '/error', failureFlash: true }),
  function(req, res) {
    req.session.passedRelayState = req.body.RelayState;
    res.redirect('/profile');
  }
);

app.post('/saml/slo',
  function (req, res, next) {
    if (req.isAuthenticated()) {
      console.log('Attempting to logout user %s via SAML SLO', req.user.subject.name);
    }
    next();
  },
  passport.authenticate('saml', { failureRedirect: '/error', failureFlash: true }),
  function(req, res) {
    res.render("logout");
  }
);

app.get("/profile", function(req, res) {
    if(req.isAuthenticated()){
      req.user.relayState = req.session.passedRelayState
      res.render("profile", req.user);
    } else {
      res.redirect('/login');
    }
});

app.get('/logout', function(req, res) {
  if (req.isAuthenticated()) {
    if (_.isString(spOptions.logoutUrl) && spOptions.logoutUrl !== 'N/A') {
      // We profile mapped the request user and need to map it back to expected profile for logout
      req.user = {
        nameID: req.user.subject.name,
        nameIDFormat: req.user.subject.format,
        sessionIndex: req.user.sessionIndex
      };
      strategy.logout(req, function(err, sloRequestUrl) {
        if(!err) {
          console.log('Sending SLO Request [%s] with Binding [HTTP-Redirect]', sloRequestUrl);
          //redirect to the IdP Logout URL
          res.redirect(sloRequestUrl);
        } else {
          throw err;
        }
      });
    } else {
      console.log('User %s successfully logged out', req.user.subject.name);
      req.session.destroy();
      res.render("logout");
    }
  } else {
    res.render("logout");
  }

});

app.get(['/settings'], function(req, res, next) {
  res.render('settings', {
    sp: spOptions
  });
});

app.post(['/settings'], function(req, res, next) {
  Object.keys(req.body).forEach(function(key) {
    switch(req.body[key].toLowerCase()){
      case "true": case "yes": case "1":
        spOptions[key] = true;
        break;
      case "false": case "no": case "0":
        spOptions[key] = false;
        break;
      default:
        spOptions[key] = req.body[key];
        break;
    }

    if (req.body[key].match(/^\d+$/)) {
      spOptions[key] = parseInt(req.body[key], '10');
    }

    strategy = new SamlStrategy(spOptions, spOptions.verify);
    passport.use(strategy);
  });

  console.log('Updated SP Configuration => \n', spOptions);
  res.redirect('/');
});

app.get('/error', function(req, res) {
  console.log(JSON.stringify(req));
});

// catch 404 and forward as relay state
app.use(function(req, res) {
  if (!req.isAuthenticated()) {
    req.session.relayState = req.originalUrl;
  }
  res.redirect('/login');
});

// development error handler
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
      message: err.message,
      error: err.status === 404 ? null : err
  });
});

/**
 * Async Start Server with Dynamic SAML Configuration
 */

startServer = function() {
  console.log();
  console.log('[SAML Service Provider]\n', spOptions)
  console.log();

  // Register SAML Strategy with Options

  strategy = new SamlStrategy(spOptions, spOptions.verify);
  passport.use(strategy);


  httpServer = argv.https ?
    https.createServer({ key: argv.httpsPrivateKey, cert: argv.httpsCert }, app) :
    http.createServer(app);


  console.log();
  console.log('starting server...');
  httpServer.listen(app.get('port'), function() {
    var scheme   = argv.https ? 'https' : 'http',
        address  = httpServer.address(),
        hostname = os.hostname();
        baseUrl  = address.address === '0.0.0.0' ?
          scheme + '://' + hostname + ':' + address.port :
          scheme + '://localhost:' + address.port;

    console.log('\n\t' + baseUrl);
    console.log();
    console.log('SP Issuer URI:\n\t' + spOptions.issuer);
    console.log('SP Audience URI:\n\t' + spOptions.audiencekey);
    console.log('SP NameID Format:\n\t' + spOptions.identifierFormat);
    console.log('SP ACS Binding:\n\turn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
    console.log('SP ACS URL:\n\t' + baseUrl + '/saml/sso')
    console.log();
    console.log('IdP SSO ACS URL:\n\t' + spOptions.entryPoint);
    console.log('IdP SLO URL:\n\t' + spOptions.logoutUrl);
    console.log('Relay State:\n\t' + spOptions.additionalParams.RelayState)
    console.log();

  });
}

// Fetch IdP Metadata and Start Server

if (argv.idpMetaUrl) {
  console.log('downloading SAML IdP metadata from ' + argv.idpMetaUrl)
  SamlMetadata.fetch(argv.idpMetaUrl, function(err, metadata) {
    console.log();
    console.log('[SAML IdP Metadata]\n', metadata);
    console.log();
    if (_.isString(metadata.sso.redirectUrl)) {
      spOptions.entryPoint = metadata.sso.redirectUrl;
    }
    if (_.isString(metadata.slo.redirectUrl)) {
      spOptions.logoutUrl = metadata.slo.redirectUrl;
    }
    spOptions.cert = metadata.signingKey || spOptions.cert;
    startServer();
  })
} else {
  startServer();
}





