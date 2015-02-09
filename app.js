
/**
 * Module dependencies.
 */

var express             = require('express'),
    os                  = require('os'),
    fs                  = require('fs'),
    http                = require('http'),
    path                = require('path'),
    hbs                 = require('hbs'),
    logger              = require('morgan'),
    cookieParser        = require('cookie-parser'),
    bodyParser          = require('body-parser'),
    session             = require('express-session'),
    passport            = require('passport'),
    yargs               = require('yargs'),
    SamlStrategy        = require('./samlstrategy');

/**
 * Globals
 */

var app                 = express(),
    server              = http.createServer(app),
    strategy,
    startServer;

/**
 * Configuration
 */

console.log();
console.log('loading configuration...');
var argv = yargs
  .usage('\nSimple SP for SAML 2.0 WebSSO Profile\n\n' +
      'Launches Web Server that trusts SAML assertions issues by an Identity Provider (IdP)\n\n' +
      'Usage:\n\t$0 --idpSsoUrl {url} --cert {pem file}\n\n$0 --idpMetaUrl {url}', {

    port: {
      description: 'Web server listener port',
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
    cert: {
      description: 'IdP Signing Certificate (PEM)',
      string: true,
      required: false
    },
    idpMetaUrl: {
      description: 'IdP SAML Metadata URL',
      string: true,
      required: false
    },
    idFormat : {
      description: 'Assertion Subject NameID Format',
      required: false,
      string: true,
      default: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'     
    }               
  })
  .example('\t$0 --idpSsoUrl http://rain.okta1.com:1802/app/raincloud59_testaiwsaml_2/exk7s3gpHWyQaKyFx0g4/sso/saml --cert ./idp-cert.pem', '')
  .check(function(argv, aliases) {

    if (argv.idpMetaUrl === undefined && 
      (argv.idpSsoUrl === undefined || argv.cert === undefined)) {

      return 'IdP SAML Metadata URL (idpMetaUrl) or IdP SSO Assertion Consumer URL (idpSsoUrl) and IdP Signing Certificate (cert) is required!'
    }

    if (argv.cert) {
      if (!fs.existsSync(argv.cert)) {
        return 'IdP Signing Certificate "' + argv.cert + '" is not a valid file path';
      }

      cert = fs.readFileSync(argv.cert);
      if (!argv.cert.match(/-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g)) {
        return 'IdP Signing Certificate "' + argv.cert + '" is not a valid PEM file';
      }
      argv.cert = cert;
    } 
  })
  .argv;


console.log();
console.log('Listener Port:\n\t' + argv.port);
console.log('SP Issuer URI:\n\t' + argv.issuer);
console.log('SP Audience URI:\n\t' + argv.audience);
console.log('SP NameID Format:\n\t' + argv.idFormat);
console.log('IdP SSO ACS URL:\n\t' + argv.idpSsoUrl);
console.log('IdP Metadata URL:\n\t' + argv.idpMetaUrl);
console.log(); 

/**
 * SAML Service Provider Configuration.
 */

var spOptions = {
  path:                 '/saml/sso',
  entryPoint:           argv.idpSsoUrl,
  issuer:               argv.issuer,
  audiencekey:          argv.audience,
  identifierFormat:     argv.idFormat,
  acceptedClockSkewMs:  2000,
  logoutUrl:            argv.sloUrl, 
  cert:                 argv.cert,
  privateCert:          fs.readFileSync('./server-key.pem', 'utf-8'),
  profileMapper:        function(profile, done) {
                          console.log('Assertion => ' + JSON.stringify(profile, null, '\t'));
                          return done(null, {
                            nameID: profile.nameID,
                            nameIdFormat: profile.nameIDFormat,
                            issuer: profile.issuer,
                            email : profile.email,
                            displayName : profile.displayName,
                            firstName : profile.firstName,
                            lastName : profile.lastName
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

app.get("/", function(req, res) {
  res.redirect('/profile');
});

app.get("/login",
  passport.authenticate('saml', { failureRedirect: '/error', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post('/saml/sso',
  passport.authenticate('saml', { failureRedirect: '/error', failureFlash: true }),
  function(req, res) {
    res.redirect('/profile');
  }
);

app.get("/profile", function(req, res) {
    if(req.isAuthenticated()){
      res.render("profile", { user: req.user });
    } else {
      res.redirect('/login');
    }
});

app.get('/logout', function(req, res) {
  if (spOptions.logoutUrl) {
    strategy.logout(req, res);
  } else {
    req.logout();
    res.redirect('/login')
  }
});

app.get('/error', function(req, res) {
  console.log(JSON.stringify(req));
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// development error handler
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
      message: err.message,
      error: err
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

  strategy = new SamlStrategy(spOptions, spOptions.profileMapper);
  passport.use(strategy);


  console.log();
  console.log('starting server...');
  server.listen(app.get('port'), function() {
    var address  = server.address(),
        hostname = os.hostname();
        baseUrl  = address.address === '0.0.0.0' ? 
          'http://' + hostname + ':' + address.port :
          'http://localhost:' + address.port
    
    console.log('listening on port: ' + app.get('port'));
    console.log();
    console.log('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
    console.log('\t=> ' + baseUrl + '/saml/sso')
    console.log();
  });
}

// Fetch IdP Metadata and Start Server

if (argv.idpMetaUrl) {
  console.log('downloading SAML IdP metadata from ' + argv.idpMetaUrl)
  SamlStrategy.parseIdentityProviderMetadata(argv.idpMetaUrl, function(err, metadata) {
    console.log();
    console.log('[SAML IdP Metadata]\n', metadata);
    console.log();
    spOptions.entryPoint = metadata.sso.redirectUrl || spOptions.idpSsoUrl;
    spOptions.cert = metadata.sso.signatureKey || spOptions.cert;
    startServer();
  })
} else {
  startServer();
}





