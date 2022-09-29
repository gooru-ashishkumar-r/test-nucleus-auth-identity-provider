var WSFEDStrategy = require('passport-wsfed-saml2').Strategy;

var PGEntitySSOConf = require('./PGEntitySSOConfigV3');
var PGEntitySSOConfig = new PGEntitySSOConf();

function WSFEDConfiguration() {
};

WSFEDConfiguration.prototype.getConfig = function(shortname, callback) {
	var params = [ shortname, 'wsfed' ];
	try {
		PGEntitySSOConfig.getSSOConfig(params, function(err, res) {
			if (!err) {
				if (typeof (res.config) == 'undefined') {
					var err = new Error("Invalid short name");
					err.status = 401;
					return callback(err, null);
				}
				var strategy = new WSFEDStrategy({
					realm : res.config.realm,
					homeRealm : res.config.homeRealm,
					identityProviderUrl : res.config.idpUrl,
					thumbprint : res.config.thumbprint
				}, function(profile, done) {
					process.nextTick(function() {
						return done(null, profile);
					})
				});
				return callback(err, strategy, res.config);
			} else {
				return callback(err, null, null);
			}
		});
	} catch (error) {
		return callback(error, null, null);
	}
};

WSFEDConfiguration.prototype.getSecret = function(client_id, callback) {
	var params = [ client_id ];
	try {
		PGEntitySSOConfig.getSecret(params, function(err, res) {
			if (res) {
				return callback(err, res.secret);
			} else {
				return callback(err, null);
			}
		});
	} catch (error) {
		return callback(error, null);
	}
};

module.exports = WSFEDConfiguration;