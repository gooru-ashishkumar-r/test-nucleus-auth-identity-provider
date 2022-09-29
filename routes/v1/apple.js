var express = require('express');
var router = express.Router();
var passport = require('passport');
var superagent = require('superagent');
var config = require(process.env.CONFIG_FILE_PATH);
var logger = require('../../log');
var AppleConfig = require('../../configuration/appleConfiguration');
var appleConfiguration = new AppleConfig();
var uuid = require('uuid-v4');
var redis = require('redis'),
  client = redis.createClient(config.redis.port, config.redis.host);

const configKeyPrefix = "Apple-";

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

var appleGetRouteHandler = function(request, response, next) {
  logger.info("v1 Apple signin entry point ...");

  var tenantId = request.query.tenantId;
  var redirectUrl = request.query.redirectUrl;
  var longLivedAccess = request.query.long_lived_access;
  logger.info("tenantId found in request:" + tenantId);

  // If there is no tenant id in the request then fallback on default from
  // config
  if (typeof(tenantId) == 'undefined') {
    tenantId = config.client_id;
  }

  logger.info("getting apple config from database for tenant:" + tenantId);
  appleConfiguration.getConfig(tenantId, function(err, strategy, appleConfig) {
    if (!err) {
      logger.debug("got config from database");
      passport.use(getConfigStorageKey(tenantId), strategy);
      var stateJson = {
        tenantId: tenantId,
        redirectUrl: redirectUrl || appleConfig.config.redirectUrl
      };
      if (longLivedAccess === 'true') {
        stateJson.long_lived_access = true;
      }
      var stateNonce = generateNonce(JSON.stringify(stateJson));

      passport.authenticate(getConfigStorageKey(tenantId), {
        scope: ['name', 'email'],
        state: stateNonce
      })(request, response)
    } else {
      logger.error("unable to get config of the tenant: " + tenantId);
      return next(err);
    }
  });
};

var applePostCallbackHandler = function(req, res, next) {
  logger.info("Processing Apple Callback Login request");
  var stateNonce = req.body.state;
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
        var requestBody = {};
        logger.info("Checking tenant:" + stateJson.tenantId);
        var clientId  = stateJson.tenantId;
        if (stateJson.long_lived_access) {
          logger.info("Received Long Lived Access Token To Generate.");
        }
        appleConfiguration.getConfig(clientId, function(err, strategy, appleConfig) {
          if (!err) {
            logger.info("got config from database");
            passport.use(getConfigStorageKey(clientId), strategy);
            passport.authenticate(getConfigStorageKey(clientId), (err, profile, info) => {
              if (!err) {
                requestBody.user = {};
                requestBody.user.first_name = profile.name ? profile.name.firstName : profile.email.split('@')[0];
                requestBody.user.last_name = profile.name ? profile.name.lastName : profile.email.split('@')[0];
                requestBody.user.reference_id = profile.email;
                requestBody.user.email = profile.email;
                requestBody.grant_type = "apple";
                logger.info("Callback from v2 apple ..." + profile.email);
                requestBody.callBackUrl = stateJson.redirectUrl;
                if (stateJson.long_lived_access) {
                  requestBody.long_lived_access = stateJson.long_lived_access;
                }
                logger.info("Performing authentication with navigator");
                authenticate(req, res, requestBody, clientId, appleConfig.secret);
              } else {
                logger.error("unable to get apple strategy method:" + clientId);
                return next(err);
              }
            })(req, res, next);
          } else {
            logger.error("unable to get config of the tenant: " +
              clientId);
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

router.get("/", appleGetRouteHandler);

router.post('/callback', applePostCallbackHandler);

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
  logger.info("persistent in redis successfully for v2 apple nonce:" + nonce);
  return nonce;
};

function authenticate(req, res, requestBody, clientId, secret) {

  var callBackUrl = requestBody.callBackUrl;
  delete requestBody.callBackUrl;

    const basicAuthToken = new Buffer((clientId + ":" + secret)).toString('base64');
    superagent.post(config.authHandlerInternalHostName + '/api/internal/v2/sso/apple')
    .send(requestBody)
    .set('user-agent',req.headers['user-agent'])
    .set('authorization', 'Basic ' + basicAuthToken).end(function(e, response) {
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
