var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var PGEntitySSOConfig = require('../repositories/PGEntitySSOConfig');
var ssoConfig = new PGEntitySSOConfig();
const config = require(process.env.CONFIG_FILE_PATH);

function GmailConfiguration() {
};

GmailConfiguration.prototype.getConfig = function(client_id, callback) {
	var params = [ client_id, 'google' ];
	try {
		ssoConfig.getSSOConfigByTenant(params, function(err, res) {
			if (!err) {
				if (typeof (res.config) == 'undefined') {
					var err = new Error("Invalid tenant");
					err.status = 401;
					return callback(err, null, null);
				}
				var strategy = new GoogleStrategy({
					clientID : res.config.clientId || config.gmail.clientID,
					clientSecret : res.config.clientSecret ||config.gmail.clientSecret ,
					callbackURL : res.config.callBackUrl || (config.baseUrl
							+ '/api/nucleus-auth-idp/v2/google/callback')
				}, function(request, accessToken, refreshToken, profile, done) {
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

module.exports = GmailConfiguration;
