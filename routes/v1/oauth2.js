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


var OAUTH2Config = require('./oauth2Configuration');
var OAUTH2Configuration = new OAUTH2Config();

const configKeyPrefix = "OAUTH2-";
const MANDATORY_CONFIG_KEYS = ["authorization_url", "client_id", "token_url", "client_secret", "scope", "callback_url", "response_type", "profile.api_url", "profile.auth_header_placeholder", "profile.response_mapper.first_name"];

router.get('/:shortname', function(req, res, next) {
  const shortname = req.params.shortname;
  LOGGER.info("v1 GET: OAuth login entry point");

  if (shortname) {
    OAUTH2Configuration.getConfig(shortname, function(err, strategy, OAUTH2Config) {
      if (!err) {
        if (validateOAuth2ConfigSettings(OAUTH2Config)) {
          var stateJson = {};
          var longLivedAccess = req.query.long_lived_access;
          if (longLivedAccess === 'true') {
            stateJson.long_lived_access = true;
          }
          var stateNonce = generateNonce(JSON.stringify(stateJson));

          passport.use(getConfigStorageKey(shortname), strategy);
          passport.authenticate(getConfigStorageKey(shortname), {
            failureRedirect: '/',
            failureFlash: true,
            state: stateNonce
          })(req, res, next);
        } else {
          LOGGER.info("Oauth2 config setting is not updated correctly, check  the mandatory key values.");
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

router.get("/:shortname/callback", (req, res, next) => {
  const shortname = req.params.shortname;
  LOGGER.info("v1 :  OAuth2 login callback entry point");
  var stateNonce = req.query.state;
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
        OAUTH2Configuration.getConfig(shortname, function(err, strategy, oauth2Config) {

          passport.use(getConfigStorageKey(shortname), strategy);

          passport.authenticate(getConfigStorageKey(shortname), (err, accessToken, profile) => {
            var profileUrl = oauth2Config.profile.api_url;
            var authHeaderPlaceholder = oauth2Config.profile.auth_header_placeholder;
            var profileResponseMapper = oauth2Config.profile.response_mapper;
            var districtResponseMapper = oauth2Config.profile.district_mapper;
            var redirectUrl = oauth2Config.home_page_url;

            profileInfo(req, res, profileUrl, authHeaderPlaceholder, accessToken, function(err, response) {
              if (!err) {
                var responseBody = flatten(response.body);
                LOGGER.info("Response from : {}", responseBody);
                var profile = profileInfoMapper(profileResponseMapper, responseBody);
                var districtInfo = profileInfoMapper(districtResponseMapper, responseBody);
                var requestBody = {
                  "grant_type": "oauth2",
                  "user": profile,
                  "ext_access_token": accessToken
                };
                if (stateJson.long_lived_access) {
                  requestBody.long_lived_access = stateJson.long_lived_access;
                }

                processAuthentication(req, res, next, redirectUrl, requestBody, districtInfo.district_id);

              } else {
                var err = new Error("Unable to get profile information, Unauthorized Access");
                err.status = 401;
                return next(err);
              }
            });
          })(req, res, next)
        });
      }
    } else {
      LOGGER.error("failed to fetch state nonce from redis");
      return next(err);
    }
  });
});

function processAuthentication(req, res, next, redirectUrl, requestBody, district) {
  OAUTH2Configuration.getTenantMapping(district, function(err, tenantInfo) {
    if (!err) {
      LOGGER.info("tenant district mapping found");
      const basicAuthToken = new Buffer((tenantInfo.tenant + ":" + tenantInfo.secret)).toString('base64');
      authenticate(req, res, redirectUrl, requestBody, basicAuthToken);
    } else {
      ErrLogger.error("District  with id '" + district + "' not found in Gooru")
      var err = new Error("District mapping not found in Gooru, Unauthorized Access");
      err.status = 401;
      return next(err);
    }
  });
};

function authenticate(req, res, redirectUrl, requestBody, basicAuthToken) {
  LOGGER.debug("redirect URL:" + redirectUrl);
  superagent.post(config.authHandlerInternalHostName + '/api/internal/v2/sso/oauth2')
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
        LOGGER.error("V1 Oauth2 Authentication failure :");
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


function profileInfo(req, res, profileUrl, authHeaderPlaceholder, accessToken, next) {
  var authorizationHeader = authHeaderPlaceholder.replace('[tokenValue]', accessToken);
  LOGGER.debug("profile info:" + profileUrl);
  superagent.get(profileUrl)
    .set('user-agent', req.headers['user-agent'])
    .set('Authorization', authorizationHeader)
    .end(function(e, response) {
      if (!e) {
        return next(null, response);
      } else {
        LOGGER.error(e);
        LOGGER.error("Failed to read profile info:");
        return next(e, null);
      }
    });
}

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

function validateOAuth2ConfigSettings(OAUTH2Config) {
  var oauth2Config = flatten(OAUTH2Config);
  var oauth2ConfigKeys = Object.keys(oauth2Config);
  for (var index = 0; index < MANDATORY_CONFIG_KEYS.length; index++) {
    var value = MANDATORY_CONFIG_KEYS[index];
    if (oauth2ConfigKeys.indexOf(value) === -1) {
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
  LOGGER.info("persistent in redis successfully for  oauth2 nonce:" + nonce);
  return nonce;
};

module.exports = router;
