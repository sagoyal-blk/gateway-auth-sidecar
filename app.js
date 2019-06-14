var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var session = require('express-session');
var passport = require('passport');
var OidcStrategy = require('passport-openidconnect').Strategy;

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'sdfsdSDFD5sf4rt4egrt4drgsdFSD4e5',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    maxAge: 300000
  }
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use('oidc', new OidcStrategy({
  issuer: 'https://dev-112030.okta.com/oauth2/default',
  authorizationURL: 'https://dev-112030.okta.com/oauth2/default/v1/authorize',
  tokenURL: 'https://dev-112030.okta.com/oauth2/default/v1/token',
  userInfoURL: 'https://dev-112030.okta.com/oauth2/default/v1/userinfo',
  clientID: '0oafki8ni93UpJuPA356',
  clientSecret: 'DtlWgh1whOVrrG9oU1jhdLMAA8Js23mJkhLgBtoS',
  callbackURL: 'http://104.154.45.109:8080/authorization-code/callback',
  scope: 'openid profile email offline_access'
}, (issuer, sub, profile, accessToken, refreshToken, done) => {
  profile['accessToken'] = accessToken;
  profile['refreshToken'] = refreshToken;
  return done(null, profile);
}));

passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
});

app.get('/api/auth-token', (req, res, next) => {
  if (req.isAuthenticated()) {
    res.send(JSON.stringify(req.user.accessToken));
  } else {
    res.status(401).send(null);
  }
});

app.get('/apps/*', (req, res, next) => {
  if (req.isAuthenticated()) {
    res.send("OK");
  } else {
    req.session.returnUrl = req.url;
    next();
  }
}, passport.authenticate('oidc'));

app.get('/authorization-code/callback',
  passport.authenticate('oidc', { failureRedirect: '/error' }),
  (req, res) => {
    res.redirect(req.session.returnUrl);
  }
);

app.get('/validate', (req, res) => {
  if (!req.isAuthenticated()) {
    res.status(401);
    res.send(null);
  } else {
    res.header("Cache-Control", "no-cache, no-store, must-revalidate");
    res.header("Pragma", "no-cache");
    res.header("Expires", 0);
    res.send("Authorized");
  }
});

app.get('/logout', (req, res) => {
  req.logout();
  req.session.destroy();
  res.redirect('/');
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
