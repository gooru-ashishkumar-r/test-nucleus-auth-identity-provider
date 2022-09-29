var express = require('express');
var router = express.Router();
var passport = require('passport');
var superagent = require('superagent');
var config = require(process.env.CONFIG_FILE_PATH);
var logger = require('../../log');
var GmailConfig = require('../../configuration/gmailConfiguration');
var GmailConfiguration = new GmailConfig();
var uuid = require('uuid-v4');
var redis = require('redis'),
  client = redis.createClient(config.redis.port, config.redis.host);

const configKeyPrefix = "Google-";

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

var gmailGetRouteHandler = function(request, response, next) {
  logger.info("v2 Google signin entry point ...");

  var tenantId = request.query.tenantId;
  var longLivedAccess = request.query.long_lived_access;
  var role = request.query.r;
  var orgId = request.query.o;
  if (role && role === 's') {
    role = 'student';
  } else if (role && role === 't') {
    role = 'teacher';
  }
  logger.info("tenantId found in request:" + tenantId);

  // If there is no tenant id in the request then fallback on default from
  // config
  if (typeof(tenantId) == 'undefined') {
    tenantId = config.client_id;
  }

  logger.info("getting gmail config from database for tenant:" + tenantId);
  GmailConfiguration.getConfig(tenantId, function(err, strategy, gmailConfig) {
    if (!err) {
      logger.debug("got config from database");
      passport.use(getConfigStorageKey(tenantId), strategy);
      var stateJson = {
        tenantId: tenantId,
        redirectUrl: gmailConfig.config.redirectUrl || config.gmail.redirectUrl
      };
      if (longLivedAccess === 'true') {
        stateJson.long_lived_access = true;
      }
      if (role) {
          stateJson.role = role;
      }
      if (orgId) {
        stateJson.orgId = orgId;
      }
      var stateNonce = generateNonce(JSON.stringify(stateJson));

      passport.authenticate(getConfigStorageKey(tenantId), {
        scope: [config.gmail.scopeProfile, config.gmail.scopeEmail],
        state: stateNonce
      })(request, response)
    } else {
      logger.error("unable to get config of the tenant: " + tenantId);
      return next(err);
    }
  });
};

var gmailGetCallbackHandler = function(req, res, next) {
  logger.info("Processing Google Callback Login request");
  var stateNonce = req.query.state;
  client.get(stateNonce, function(err, stateData) {
    if (!err) {
      if (!stateData) {
        logger.error("unable to get config of the tenant: ");
        logger.error(err);
        var err = new Error("Unauthorized Access");
        err.status = 401;
        return next(err);
      } else {
        var stateJson = JSON.parse(stateData);
        var options = {};
        options.client_id = stateJson.tenantId;
        logger.info("Checking tenant:" + stateJson.tenantId);
        if (stateJson.long_lived_access) {
          logger.info("Received Long Lived Access Token To Generate.");
        }
        GmailConfiguration.getConfig(options.client_id, function(err, strategy, gmailConfig) {
          if (!err) {
            logger.info("got config from database");
            passport.use(getConfigStorageKey(options.client_id), strategy);
            passport.authenticate(getConfigStorageKey(options.client_id), (err, profile, info) => {
              if (!err) {
                options.user = {};
                options.user.first_name = profile._json.given_name;
                options.user.last_name = profile._json.family_name;
                options.user.identity_id = profile._json.email;
                if (stateJson.role) {
                  options.user.user_category = stateJson.role;
                }
                if (stateJson.orgId) {
                  options.user.school_id = stateJson.orgId;
                }
                options.grant_type = "google";
                logger.info("Callback from v2 google ..." + profile._json.email);
                options.client_key = gmailConfig.secret;
                var requiredDomains = gmailConfig.config.domains;
                logger.info("veryfying email domains:" + requiredDomains);
                options.callBackUrl = stateJson.redirectUrl;
                if (stateJson.long_lived_access) {
                  options.long_lived_access = stateJson.long_lived_access;
                }
                if (requiredDomains) {
                  logger.info("not null domains");
                  if (isVerifiedDomain(options.user.identity_id,
                      requiredDomains)) {
                    logger.info("email domain verified successfully");
                    authenticate(req, res, options);
                  } else {
                    logger.info("Unauthorized domain");
                    var err = new Error("Access from unauthorized domain");
                    err.status = 403;
                    return next(err);
                  }
                } else {
                  logger.info("null domains");
                  authenticate(req, res, options);
                }
              } else {
                logger.error("unable to get google strategy method:" + options.client_id);
                return next(err);
              }
            })(req, res, next);
          } else {
            logger.error("unable to get config of the tenant: " +
              options.client_id);
            var err = new Error("Unauthorized Access");
            err.status = 401;
            return next(err);
          }
        });
      }
    } else {
      logger.error("failed to fetch state nonce from redis");
      return next(err);
    }
  });
};

router.get("/", gmailGetRouteHandler);

router.get('/callback', gmailGetCallbackHandler);

function isVerifiedDomain(email, requiredDomains) {
  var emailDomain = email.split('@')[1];
  var requiredDomainsArray = JSON.stringify(requiredDomains);
  return requiredDomainsArray.includes(emailDomain);
}

function getConfigStorageKey(id) {
  return configKeyPrefix + id;
}

function generateNonce(stateJson) {
  if (typeof(stateJson) === "undefined" || stateJson.length == 0) {
    logger.debug("no state json string present, skipping nonce generation");
    return;
  }

  logger.info("generating nonce..")
  var nonce = uuid();
  logger.info("persisting in redis");
  client.set(nonce, stateJson, 'EX', config.redis.expiryInMinutes * 60);
  logger.info("persistent in redis successfully for v2 google nonce:" + nonce);
  return nonce;
};

function authenticate(req, res, options) {

  var callBackUrl = options.callBackUrl;
  delete options.callBackUrl;
  superagent
    .post(config.hostname + '/api/nucleus-auth/v1/authorize')
    .send(options)
    .set('user-agent', req.headers['user-agent'])
    .end(
      function(e, response) {
        var xForward = typeof(req.headers['x-forwarded-proto']) !== "undefined" ? req.headers['x-forwarded-proto'] :
          req.protocol;
        var domainName = xForward + '://' + config.domainName;
        if (!e &&
          (response.status == 200 || response.status == 201)) {
          var json = JSON.parse(response.text);
          res.statusCode = 302;
          var redirectUrl = null;

          if (typeof(callBackUrl) !== 'undefined') {
            redirectUrl = callBackUrl
          } else {
            redirectUrl = domainName;
          }

          if (redirectUrl.indexOf("?") >= 0) {
            redirectUrl += "&access_token=" +
              json.access_token;
          } else {
            redirectUrl += "?access_token=" +
              json.access_token;
          }

          res.setHeader('Location', redirectUrl);
        } else {
          logger.error(" Authentication failure :");
          logger.error(response.text);
          res.statusCode = 302;
          res.setHeader('Location', domainName);
        }
        res.end();
      });

}

module.exports = router;
