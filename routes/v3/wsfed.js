var express = require('express');
var router = express.Router();
var passport = require('passport');
var config = require(process.env.CONFIG_FILE_PATH);
var LOGGER = require('../../log');
var queryString = require('qs');
var superagent = require('superagent');
var uuid = require('uuid-v4');
var Map = require('collections/map');

var redis = require('redis'),
  client = redis.createClient(config.redis.port, config.redis.host);

var WSFEDConfig = require('./wsfedConfigurationV3');
var WSFEDConfiguration = new WSFEDConfig();

const configKeyPrefix = "WSFED-";
const NONCE = "NONCE";

router.get('/login/:shortname', function(req, res, next) {
  LOGGER.info("v3: GET entry")
  const shortname = req.params.shortname;
  LOGGER.info("v3 : wsfed signin entry point for partner :=" + shortname);

  const context = req.query.context;
  var stateJson = {
    context: context
  };
  var longLivedAccess = req.query.long_lived_access;
  if (longLivedAccess === 'true') {
    stateJson.long_lived_access = true;
  }

  if (typeof(shortname) != 'undefined') {
    WSFEDConfiguration.getConfig(shortname, function(err, strategy, wsfedConfig) {
      if (!err) {
        passport.use(getConfigStorageKey(shortname), strategy);
        passport.authenticate(getConfigStorageKey(shortname), {
          failureRedirect: '/',
          failureFlash: true,
          wctx: generateNonce(JSON.stringify(stateJson))
        })(req, res, next);
      } else {
        return next(err);
      }
    });
  } else {
    var err = new Error("Unauthorized Access");
    err.status = 401;
    return next(err);
  }
});

router.post("/login/:shortname", (req, res, next) => {
  LOGGER.info("v3: Processing POST Login request");
  const wctx = req.body.wctx;
  LOGGER.info("received wctx:" + wctx);
  const requestBody = {};
  const shortname = req.params.shortname;
  // Parse wctx and generate map
  const wctxMap = parseContext(wctx);

  WSFEDConfiguration.getConfig(shortname, function(err, strategy, wsfedConfig) {
    passport.use(getConfigStorageKey(shortname), strategy);

    passport.authenticate(getConfigStorageKey(shortname), (err, profile, info) => {
      if (err) {
        return next(err);
      }
      requestBody.user = {};
      requestBody.user.first_name = profile['http://identityserver.thinktecture.com/claims/profileclaims/firstname'];
      requestBody.user.last_name = profile['http://identityserver.thinktecture.com/claims/profileclaims/lastname'];

      var role = profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'];
      requestBody.grant_type = "wsfed";

      var account_id = profile['http://identityserver.thinktecture.com/claims/profileclaims/accountguid'];
      if (account_id != null) {
        requestBody.user.reference_id = account_id;
      }

      var username = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'];
      if (username != null) {
        requestBody.user.username = username;
      }

      var email = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'];
      if (email != null) {
        requestBody.user.email = email;
      }

      // Get client id from the claim
      const clientId = profile['http://gooru.org/tenant/clientid'];
      LOGGER.info("client id received:" + clientId);

      // Get Nonce from wctx
      var nonce = getNonce(wctxMap);
      LOGGER.info("nonce extracted from wctx:" + nonce);

      // If nonce is present in wctx then use it as redirect url. Assuming
      // that redirect url is stored in
      // nonce while initiating the request. If not present then load
      // default gooru home page.
      if (typeof(nonce) === "undefined" || nonce.length == 0) {
        LOGGER.debug("nonce is not present in context");
        processAuthentication(req, res, wsfedConfig.homeRealm, requestBody, clientId);
      } else {
        client.get(nonce, function(err, reply) {
          if (!err) {
            var wctxMapJson = JSON.parse(reply);
            if (wctxMapJson.long_lived_access) {
              LOGGER.info("Received Long Lived Access Token To Generate.");
              requestBody.long_lived_access = stateJson.long_lived_access;
            }
            var context = wctxMapJson.context ? wctxMapJson.context : wsfedConfig.homeRealm;
            processAuthentication(req, res, context, requestBody, clientId);
          } else {
            processAuthentication(req, res, wsfedConfig.homeRealm, requestBody, clientId);
          }
        });
      }

    })(req, res, next)
  });
});

function processAuthentication(req, res, redirectUrl, requestBody, clientId) {
  WSFEDConfiguration.getSecret(clientId, function(error, secret) {
    if (!error) {
      LOGGER.debug("got secret from database");
      const basicAuthToken = new Buffer((clientId + ":" + secret)).toString('base64');
      authenticate(req, res, redirectUrl, requestBody, basicAuthToken);
    } else {
      LOGGER.error("unable to get secret for the client:" + clientId);
      return next(error);
    }
  });
}

function authenticate(req, res, redirectUrl, requestBody, basicAuthToken) {
  LOGGER.debug("redirect URL:" + redirectUrl);
  superagent.post(config.authHandlerInternalHostName + '/api/internal/v2/sso/wsfed')
    .send(requestBody)
    .set('user-agent', req.headers['user-agent'])
    .set('authorization', 'Basic ' + basicAuthToken)
    .end(function(e, response) {
      var xForward = typeof(req.headers['x-forwarded-proto']) !== "undefined" ? req.headers['x-forwarded-proto'] : req.protocol;
      var domainName = xForward + '://' + config.domainName;
      if (!e && (response.status == 200 || response.status == 201)) {
        var json = JSON.parse(response.text);

        if (redirectUrl == null || redirectUrl.length <= 0) {
          redirectUrl = domainName;
        }

        if (redirectUrl.indexOf("?") >= 0) {
          redirectUrl += "&access_token=" + json.access_token;
        } else {
          redirectUrl += "?access_token=" + json.access_token;
        }

        res.statusCode = 302;
        res.setHeader('Location', redirectUrl);
      } else {
        LOGGER.error("V3 WSFED Authentication failure :");
        LOGGER.error(response.text);
        res.statusCode = 302;
        res.setHeader('Location', domainName);
      }
      res.end();
    });
}

function getConfigStorageKey(id) {
  return configKeyPrefix + id;
};

function parseContext(wctx) {
  var wctxMap = new Map();
  if (typeof(wctx) === "undefined" || wctx.length == 0) {
    return wctxMap;
  }

  var result = wctx.split(",");
  result.forEach(function(element) {
    var arrElements = element.split("=");
    wctxMap.set(arrElements[0], arrElements[1]);
  });

  return wctxMap;
};

function getNonce(wctxMap) {
  return wctxMap != null ? wctxMap.get(NONCE) : null;
};

function generateNonce(context) {
  if (typeof(context) === "undefined" || context.length == 0) {
    LOGGER.debug("no context present, skipping nonce generation");
    return;
  }

  LOGGER.info("generating nonce..")
  var nonce = uuid();
  LOGGER.info("persisting in redis");
  client.set(nonce, context, 'EX', config.redis.expiryInMinutes * 60);
  LOGGER.info("persistent in redis successfully for nonce:" + nonce);
  return NONCE + "=" + nonce;
};

module.exports = router;
