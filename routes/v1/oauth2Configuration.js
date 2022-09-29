var OAuth2Strategy = require('passport-oauth2').Strategy;
const PGEntitySSOConf = require('../../repositories/PGEntitySSOConfig');
const PGEntitySSOConfig = new PGEntitySSOConf();

const PGEntityTenantDistrictMapping = require('../../repositories/PGEntityTenantDistrictMapping');
const PGEntityMapping = new PGEntityTenantDistrictMapping();

function OAUTH2Configuration() {};

OAUTH2Configuration.prototype.getConfig = function(shortname, callback) {
  const params = [shortname, 'oauth2'];
  try {
    PGEntitySSOConfig.getSSOConfigByShortname(params, function(err, res) {
      if (!err) {
        if (typeof(res.config) == 'undefined') {
          var err = new Error("Invalid short name");
          err.status = 401;
          return callback(err, null);
        }
        let customHeaders = {};
        if (res.config.authorization_header) {
          customHeaders['Authorization'] = res.config.authorization_header;
        }

        const strategy = new OAuth2Strategy({
          authorizationURL: res.config.authorization_url,
          tokenURL: res.config.token_url,
          clientID: res.config.client_id,
          clientSecret: res.config.client_secret,
          responseType: res.config.response_type,
          callbackURL: res.config.callback_url,
          scope: res.config.scope,
          customHeaders: customHeaders
        }, function(accessToken, refreshToken, params, profile, done) {
          process.nextTick(function() {
            return done(null, accessToken, profile);
          })
        });
        return callback(err, strategy, res.config, res.id, res.secret);
      } else {
        return callback(err, null, null);
      }
    });
  } catch (error) {
    return callback(error, null, null);
  }
};

OAUTH2Configuration.prototype.getTenantMapping = function(districtId, callback) {
  const params = [districtId];
  try {
    PGEntityMapping.getTenantMapping(params, function(err, res) {
      if (!err) {
        return callback(err, res);
      } else {
        return callback(err, null);
      }
    });
  } catch (error) {
    return callback(error, null);
  }
};


module.exports = OAUTH2Configuration;
