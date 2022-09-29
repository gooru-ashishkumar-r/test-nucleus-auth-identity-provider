var express = require('express');
var router = express.Router();
var passport = require('passport');
var wsfedsaml2 = require('passport-wsfed-saml2').Strategy;
var config = require(process.env.CONFIG_FILE_PATH);
var logger = require('../log');
var authenticate = require('./authenticate');
passport.use(new wsfedsaml2({
	realm : config.wsfed.realm,
	homeRealm : config.wsfed.realm,
	identityProviderUrl : config.wsfed.idpUrl,
	thumbprint : config.wsfed.thumbprint
}, function(profile, done) {

	process.nextTick(function() {
		return done(null, profile);
	})
}));

router.get('/login', function(req, res) {
	logger.info("Wsfed signin entry point ...");
	var callbackUrl = req.query.redirectURI;
	if (typeof (callbackUrl) == 'undefined' || callbackUrl.length == 0) {
		callbackUrl = req.protocol + '://' + config.domainName;
	}
	passport.authenticate('wsfed-saml2', {
		failureRedirect : '/',
		failureFlash : true,
		wreply : callbackUrl
	})(req, res);

});

router
		.post(
				'/login',
				passport.authenticate('wsfed-saml2', {
					failureRedirect : '/',
					failureFlash : true
				}),
				function(req, res) {
					var profile = req.user;
					var username = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'];
					var options = {};
					options.user = {};
					options.user.firstname = (profile.fisrtname != null ? profile['http://identityserver.thinktecture.com/claims/profileclaims/firstname']
							: "firstname");
					options.user.lastname = (profile.lastname != null ? profile['http://identityserver.thinktecture.com/claims/profileclaims/lastname']
							: "lastname");
					var role = profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'];
					options.grant_type = "wsfed";
					options.user.username = "SBLMP"
							+ username.replace(/[^a-z\d\s]+/gi, "");
					options.user.username = options.user.username.substring(0,
							18);

					if (profile.email != null) {
						options.user.identity_id = profile.email;
					} else {
						options.user.identity_id = options.user.username;
					}
					if (role != null) {
						if (role == "Student" || role == "student") {
							options.user.user_category = "student";
						} else if (role == "Instructor" || role == "instructor"
								|| options.role == "Teacher"
								|| options.role == "teacher") {
							options.user.user_category = "teacher";
						} else {
							options.user.user_category = "Other";
						}
					}
					new authenticate(req, res, options);

				});

module.exports = router;
