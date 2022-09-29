var express = require('express');
var router = express.Router();
var passport = require('passport');
var config = require(process.env.CONFIG_FILE_PATH);
var LOGGER = require('../../log');
var ErrLogger = require('../../ErrorLog');
var queryString = require('qs');
var superagent = require('superagent');
var flatten = require('flat');
var uuid = require('uuid-v4');
var redis = require('redis'),
  client = redis.createClient(config.redis.port, config.redis.host);


var SAMLConfig = require('./samlConfiguration');
var SAMLConfiguration = new SAMLConfig();

const configKeyPrefix = "SAML-";
const MANDATORY_CONFIG_KEYS = ["callback_url", "entry_point", "cert", "issuer"];

router.get('/:shortname', function(req, res, next) {
  const shortname = req.params.shortname;
  LOGGER.info("v2 GET: Saml login entry point");
  if (shortname) {
    var stateJson = {};
    var longLivedAccess = req.query.long_lived_access;
    if (longLivedAccess === 'true') {
      stateJson.long_lived_access = true;
    }
    var stateNonce = generateNonce(JSON.stringify(stateJson));

    SAMLConfiguration.getConfig(shortname, stateNonce,  function(err, strategy, SAMLConfig) {
      if (!err) {
        if (validatesamlConfigSettings(SAMLConfig)) {
          passport.use(getConfigStorageKey(shortname), strategy);
          passport.authenticate(getConfigStorageKey(shortname), {
            failureRedirect: '/',
            failureFlash: true,
						requestMethod : 'post'
          })(req, res, next);
        } else {
          LOGGER.info("SAML config setting is not updated correctly, check  the mandatory key values.");
          var err = new Error("Internal server error");
          err.status = 500;
          return next(err);
        }
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

router.post("/:shortname/callback", (req, res, next) => {
  const shortname = req.params.shortname;
  LOGGER.info("v2 :  SAML login callback entry point");
  var stateNonce = req.body.RelayState;

  client.get(stateNonce, function(err, stateData) {
    if (!err) {
      if (!stateData) {
        LOGGER.error("unable to get config of the tenant: ");
        LOGGER.error(err);
        var err = new Error("Unauthorized Access");
        err.status = 401;
        return next(err);
      } else {
        var stateJson = JSON.parse(stateData);
        var options = {};
        if (stateJson.long_lived_access) {
          LOGGER.info("Received Long Lived Access Token To Generate.");
        }
        SAMLConfiguration.getConfig(shortname, stateNonce, function(err, strategy, samlConfig) {

          passport.use(getConfigStorageKey(shortname), strategy);

          passport.authenticate(getConfigStorageKey(shortname), (err,  profile, config) => {

            var profileResponseMapper = samlConfig.response_mapper;
            var districtResponseMapper = samlConfig.district_mapper;
            var isAuthorizeByDistrictInfo = districtResponseMapper ? true : false;
            var redirectUrl = samlConfig.home_page_url;
              if (!err) {
                var responseBody = flatten(profile);
                LOGGER.info("Response from : {}", responseBody);

                var profile = profileInfoMapper(profileResponseMapper, responseBody);
                var districtInfo = profileInfoMapper(districtResponseMapper, responseBody);
                var requestBody = {
                  "grant_type": "saml",
                  "user": profile
                };
                if (stateJson.long_lived_access) {
                  requestBody.long_lived_access = stateJson.long_lived_access;
                }

                processAuthentication(req, res, next, redirectUrl, requestBody, config.id, config.secret, isAuthorizeByDistrictInfo, districtInfo.district_id);
              } else {
                LOGGER.error("v2 SAML Authentication failed : {}", err);
                var err = new Error("Unable to get profile information, Unauthorized Access");
                err.status = 401;
                return next(err);
              }
          })(req, res, next)
        });
      }
    } else {
      LOGGER.error("failed to fetch state nonce from redis");
      return next(err);
    }
  });
});

function processAuthentication(req, res, next, redirectUrl, requestBody, tenantId, tenantSecret, isAuthorizeByDistrictInfo, districtId) {
  if (isAuthorizeByDistrictInfo && districtId) {
    SAMLConfiguration.getTenantMapping(districtId, function(err, tenantInfo) {
      if (!err) {
        LOGGER.info("tenant district mapping found");
        const basicAuthToken = new Buffer((tenantInfo.tenant + ":" + tenantInfo.secret)).toString('base64');
        authenticate(req, res, redirectUrl, requestBody, basicAuthToken);
      } else {
        ErrLogger.error("District  with id '" + district + "' not found in Gooru")
        var err = new Error("District mapping not found, Unauthorized Access");
        err.status = 401;
        return next(err);
      }
    });
  } else {
    const basicAuthToken = new Buffer((tenantId + ":" + tenantSecret)).toString('base64');
  	authenticate(req, res, redirectUrl, requestBody, basicAuthToken);
  }
};

function authenticate(req, res, redirectUrl, requestBody, basicAuthToken) {
  LOGGER.debug("redirect URL:" + redirectUrl);
  superagent.post(config.authHandlerInternalHostName + '/api/internal/v2/sso/saml')
    .send(JSON.stringify(requestBody))
    .set('user-agent', req.headers['user-agent'])
    .set('authorization', 'Basic ' + basicAuthToken)
    .end(function(e, response) {
      var xForward = typeof(req.headers['x-forwarded-proto']) !== "undefined" ? req.headers['x-forwarded-proto'] : req.protocol;
      var domainName = xForward + '://' + config.domainName;
      if (redirectUrl == null || redirectUrl.length <= 0) {
        redirectUrl = domainName;
      }
      if (!e && (response.status == 200 || response.status == 201)) {
        var json = JSON.parse(response.text);
        if (redirectUrl.indexOf("?") >= 0) {
          redirectUrl += "&access_token=" + json.access_token;
        } else {
          redirectUrl += "?access_token=" + json.access_token;
        }
        res.statusCode = 302;
        res.setHeader('Location', redirectUrl);
      } else {
        LOGGER.error("V2 Saml Authentication failure :");
        if (response) {
          LOGGER.error(response.text);
        }
        res.statusCode = 302;
        res.setHeader('Location', redirectUrl);
      }
      res.end();
    });
}

function getConfigStorageKey(id) {
  return configKeyPrefix + id;
};

function profileInfoMapper(profileResponseMapper, profileInfo) {
  var profile = {};
  for (var key in profileResponseMapper) {
    if (profileResponseMapper.hasOwnProperty(key)) {
      var value = profileResponseMapper[key];
      var profileData = profileInfo[value];
      if (profileData) {
        profile[key] = profileData.toString();
      }
    }
  }
  return profile;
}

function validatesamlConfigSettings(samlConfig) {
  var samlConfig = flatten(samlConfig);
  var samlConfigKeys = Object.keys(samlConfig);
  for (var index = 0; index < MANDATORY_CONFIG_KEYS.length; index++) {
    var value = MANDATORY_CONFIG_KEYS[index];
    if (samlConfigKeys.indexOf(value) === -1) {
      return false;
    }
  }
  return true;
}

function generateNonce(stateJson) {
  if (typeof(stateJson) === "undefined") {
    LOGGER.debug("no state json string present, skipping nonce generation");
    return;
  }

  LOGGER.info("generating nonce..")
  var nonce = uuid();
  LOGGER.info("persisting in redis");
  client.set(nonce, stateJson, 'EX', config.redis.expiryInMinutes * 60);
  LOGGER.info("persistent in redis successfully for  saml nonce:" + nonce);
  return nonce;
};

module.exports = router;
