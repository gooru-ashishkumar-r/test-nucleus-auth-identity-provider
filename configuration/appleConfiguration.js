const fs = require('fs');
var AppleStrategy = require('@nicokaiser/passport-apple').Strategy;
var PGEntitySSOConfig = require('../repositories/PGEntitySSOConfig');
var ssoConfig = new PGEntitySSOConfig();
const config = require(process.env.CONFIG_FILE_PATH);

function AppleConfiguration() {
};

AppleConfiguration.prototype.getConfig = function(client_id, callback) {
	var params = [ client_id, 'apple' ];
	try {
		ssoConfig.getSSOConfigByTenant(params, function(err, res) {
			if (!err) {
				if (typeof (res.config) == 'undefined') {
					var err = new Error("Invalid tenant");
					err.status = 401;
					return callback(err, null, null);
				}

				var strategy = new AppleStrategy({
					clientID : res.config.clientId,
					teamID : res.config.teamId,
					callbackURL : res.config.callBackUrl,
					keyID: res.config.keyId,
					key: fs.readFileSync(res.config.privateKeyLoc),
					scope: ['name', 'email']
				}, function(accessToken, refreshToken, profile,done) {
					process.nextTick(function() {
						return done(null, profile);
					})
				});
				return callback(err, strategy, res);
			} else {
				return callback(err, null, null);
			}
		});
	} catch (error) {
		return callback(error, null, null);
	}
};

module.exports = AppleConfiguration;
