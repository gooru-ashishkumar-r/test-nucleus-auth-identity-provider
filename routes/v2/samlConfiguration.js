var SamlStrategy = require('passport-saml');
const PGEntitySSOConf = require('../../repositories/PGEntitySSOConfig');
const PGEntitySSOConfig = new PGEntitySSOConf();

const PGEntityTenantDistrictMapping = require('../../repositories/PGEntityTenantDistrictMapping');
const PGEntityMapping = new PGEntityTenantDistrictMapping();

function SAMLConfiguration() {};

SAMLConfiguration.prototype.getConfig = function(shortname, stateNonce, callback) {
  const params = [shortname, 'saml'];
  try {
    PGEntitySSOConfig.getSSOConfigByShortname(params, function(err, res) {
      if (!err) {
        if (typeof(res.config) == 'undefined') {
          var err = new Error("Invalid short name");
          err.status = 401;
          return callback(err, null);
        }
        var additionalParams = {};
        if (res.config.custom_state_name) {
          additionalParams[res.config.custom_state_name] =  stateNonce;
        } else {
          additionalParams = {'RelayState': stateNonce};
        }
        if (res.config.additional_params) {
          additionalParams = Object.assign(additionalParams, res.config.additional_params);
        }
        
        var strategy = new SamlStrategy.Strategy({
        	callbackUrl : res.config.callback_url,
        	entryPoint : res.config.entry_point,
        	cert : res.config.cert,
        	issuer : res.config.issuer,
          identifierFormat: res.config.identifier_format || 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
          additionalParams: additionalParams
        }, function(profile, done) {
        	process.nextTick(function() {
        		return done(null, profile, res);
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

SAMLConfiguration.prototype.getTenantMapping = function(districtId, callback) {
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


module.exports = SAMLConfiguration;
