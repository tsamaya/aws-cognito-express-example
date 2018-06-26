const express = require('express');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const dotenv = require('dotenv');
const debug = require('debug')('cognito-example:server');
const path = require('path');
const AWS = require('aws-sdk');
const moment = require('moment');

const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

dotenv.config();

const port = process.env.PORT || 3000;

const restrictedDomains = process.env.DOMAIN_EMAILS;
// Domain restriction depends on env variable DOMAIN_EMAILS value.
// undefined => no restriction : maybe not what you need! But ideal for a sample
const isRestrictedDomains =
  typeof restrictedDomains !== 'undefined' && restrictedDomains !== '';

// ////////////////////////////////////////////////////////////////////////////
//
// Email Domains
//
debug(
  `restrictedDomains are ${restrictedDomains} and isRestrictedDomains is ${isRestrictedDomains}`
);

const getEmailsFromPassportProfile = profile => {
  if (typeof profile === 'undefined' || profile === null) {
    return undefined;
  } else if (typeof profile.emails === 'undefined' || profile.emails === null) {
    return undefined;
  }
  if (Array.isArray(profile.emails)) {
    return profile.emails;
  }
  return undefined;
};

const emailsContainsRestrictedDomaine = (emails, allowed) => {
  let result = false;
  const allowedEmails = allowed.split(',');
  for (let i = 0; i < allowedEmails.length && !result; i += 1) {
    for (let j = 0; j < emails.length && !result; j += 1) {
      if (emails[j].value.endsWith(allowedEmails[i])) {
        result = true;
      }
    }
  }
  return result;
};

// ////////////////////////////////////////////////////////////////////////////
//
// Configure Passport authenticated user serialization.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session. In a
// production-quality application, this would typically be as simple as
// supplying the user ID when serializing, and querying the user record by ID
// from the database when deserializing. However, due to the fact that this
// example does not have a database, the complete Google profile is serialized
// and deserialized.
//
passport.serializeUser((user, done) => {
  // done(null, user.id);
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// Configure the Google strategy for use by Passport.
//
// OAuth 2.0-based strategies require a `verify` function which receives the
// credential (`accessToken`) for accessing the Third Party API (Google) on
// the user's behalf, along with the user's profile. The function must invoke
// `done` with a user object, which will be set at `req.user` in route handlers
// after authentication.
//
//   See http://passportjs.org/docs/configure#verify-callback
passport.use(
  new GoogleStrategy(
    // The OAuth 2 client ID and secret from https://console.developers.google.com
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK,
    },

    (accessToken, refreshToken, params, profile, done) =>
      // In this example, the user's Google profile is supplied as the user
      // record.
      // In a production-quality application, the Google profile should
      // be associated with a user record in the application's database, which
      // allows for account linking and authentication with other identity
      // providers.
      process.nextTick(() => {
        const emails = getEmailsFromPassportProfile(profile);
        if (
          isRestrictedDomains &&
          !emailsContainsRestrictedDomaine(emails, restrictedDomains)
        ) {
          done(null, false, { message: 'Invalid Domain' });
        } else {
          const user = profile;
          user.token = params.id_token;
          // debug('accessToken', accessToken);
          // debug('refreshToken', refreshToken);
          // debug('params', params);
          // debug('profile', profile);
          done(null, user);
        }
      })
  )
);

// Route middleware to ensure user is authorized
const isAuthorized = (req, res, next) => {
  if (req.isAuthenticated()) {
    next();
    return;
  }
  res.redirect('/');
};

// ////////////////////////////////////////////////////////////////////////////
//
// Express app
//
// Create a new Express application.
const app = express();
// Configure view engine to render Handlebars templates.
app.set('view engine', 'hbs');
// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(
  session({
    secret: 'cognito oauth2 exampple',
    resave: false,
    saveUninitialized: false,
  })
);
// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(path.join(__dirname, 'public')));

// ////////////////////////////////////////////////////////
//
// Application routes
//
app.get('/', (req, res) => {
  res.render('index', {
    user: req.user,
  });
});

// GET /auth/google
//   Use passport.authenticate() as route middleware to authenticate the
//   request. The first step in Google authentication will involve
//   redirecting the user to google.com. After authorization, Google
//   will redirect the user back to this application at /auth/google/callback
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['email', 'profile'] })
);

// GET /auth/google/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request. If authentication fails, the user will be redirected back to the
//   login page. Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/',
  }),
  (req, res) => {
    res.redirect('/sucess');
  }
);

app.get('/sucess', isAuthorized, (req, res) => {
  AWS.config.region = process.env.COGNITO_AWS_REGION;
  const params = {
    AccountId: process.env.AWS_ACCOUNT_ID, // AWS account Id
    IdentityPoolId: process.env.COGNITO_IDENTITY_POOL_ID, // ID of the identity pool
    Logins: {
      'accounts.google.com': req.user.token,
    },
  };
  // initialize the Credentials object
  AWS.config.credentials = new AWS.CognitoIdentityCredentials(params);

  // Get the credentials for our user
  AWS.config.credentials.get(err => {
    if (err) {
      req.logout(); // invalidate user
      debug(`## credentials.get: err is ${err}`); // an error occurred
      const error = {
        message: err.message,
        status: err.status || 500,
        error: err,
      };
      if (app.get('env') === 'development') {
        error.error = {};
      }
      res.render('error', error);
    } else {
      req.user.identityId = AWS.config.credentials.identityId;
      // debug(`identityId is [${req.user.identityId}]`);
      // Other AWS SDKs will automatically use the Cognito Credentials provider
      // configured in the JavaScript SDK.
      const cognitosync = new AWS.CognitoSync();
      cognitosync.listRecords(
        {
          DatasetName: process.env.COGNITO_DATASET_NAME,
          IdentityId: req.user.identityId, // required
          IdentityPoolId: process.env.COGNITO_IDENTITY_POOL_ID, // required
        },
        (errSync, dataSync) => {
          if (errSync) {
            debug(`## listRecords: ${errSync}`); // an error occurred
            res.redirect('/');
          } else {
            // Retrieve information on the dataset
            const dataRecords = JSON.stringify(dataSync.Records);

            debug(`dataSync ${dataRecords}`);
            // Retrieve dataset metadata and SyncSessionToken for subsequent calls
            req.user.syncSessionToken = dataSync.SyncSessionToken;
            req.user.datasetSyncCount = dataSync.DatasetSyncCount;

            // Check the existence of the key in the dataset
            if (dataSync.Count !== 0) {
              req.user.lastLogin = dataSync.Records[0].Value;
              debug(`previous value is ${req.user.lastLogin}`);
            } else {
              req.user.lastLogin = Date.now();
              debug(`no previous value so ${req.user.lastLogin}`);
            }

            const ip =
              req.headers['x-forwarded-for'] || req.connection.remoteAddress;

            const lasLoginUpdated = moment()
              .utc()
              .format();

            // Parameters for updating the dataset
            const paramsSync = {
              DatasetName: process.env.COGNITO_DATASET_NAME,
              IdentityId: req.user.identityId,
              IdentityPoolId: process.env.COGNITO_IDENTITY_POOL_ID,
              SyncSessionToken: req.user.syncSessionToken,
              RecordPatches: [
                {
                  Key: 'LASTLOGIN',
                  Op: 'replace',
                  SyncCount: req.user.datasetSyncCount,
                  Value: lasLoginUpdated,
                },
              ],
            };

            // Make the call to Amazon Cognito
            cognitosync.updateRecords(paramsSync, (errUpdate, dataUpdate) => {
              if (errUpdate) {
                debug(`## updateRecords: ${errUpdate}`); // an error occurred
                res.render('error', {
                  message: `## updateRecords: ${errUpdate}`,
                  error: {
                    status: 400,
                    stack: errUpdate.stack,
                  },
                });
              } else {
                const dataRecordsNew = JSON.stringify(dataUpdate);
                res.render('success', {
                  user: req.user,
                  records: dataRecords,
                  recordsNew: dataRecordsNew,
                  lastLogin: req.user.lastLogin,
                  ip,
                  cognitoId: req.user.identityId,
                });
              }
            });
          }
        }
      );
    }
  });
});

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});
// ////////////////////////////////////////////////////////////////////////////
//
// 404 Handler to forward to the error handler
//
app.use((req, res, next) => {
  const err = new Error('Not Found');
  err.status = 404;
  next(err);
});
//
// error handler
//
app.use((err, req, res /* next */) => {
  const error = {
    message: err.message,
    status: err.status || 500,
    error: err,
  };
  res.status(error.status);
  if (app.get('env') === 'development') {
    error.error = {};
  }
  res.render('error', error);
});

app.listen(port, () => {
  console.log(`Listening on port ${port}...`); // eslint-disable-line
});
