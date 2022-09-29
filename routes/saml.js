var express = require('express');
var router = express.Router();
var Passport = require('passport').Passport;
var SamlStrategy = require('passport-saml');
var config = require(process.env.CONFIG_FILE_PATH);
var logger = require('../log');
var authenticate = require('./authenticate');
var fs = require('fs');

var passport = new Passport();

passport.serializeUser(function(user, done) {
	done(null, user);
});
passport.deserializeUser(function(user, done) {
	done(null, user);
});
var samlStrategy = new SamlStrategy.Strategy({
	callbackUrl : config.baseUrl + '/api/nucleus-auth-idp/v1/saml/callback',
	entryPoint : config.saml.entryPoint,
	cert : config.saml.certificate,
	issuer : config.saml.issuer
}, function(profile, done) {
	process.nextTick(function() {
		return done(null, profile);
	})
});

passport.use(samlStrategy);

router.get('/', passport.authenticate('saml', {
	failureRedirect : '/',
	failureFlash : true,
	requestMethod : 'post'
}));

router.post('/callback', passport.authenticate('saml', {
	failureRedirect : '/',
	failureFlash : true
}), function(req, res) {
	var profile = req.user;
	var options = {};
	options.user = {};
	var username = profile.email;
	options.user.firstname = (profile.firstName != null ? profile.firstName
			: "firstname");
	options.user.lastname = (profile.lastName != null ? profile.lastName
			: "lastName");
	options.user.identity_id = profile.email;
	options.grant_type = "SAML";
	options.user.username = "BNCOPEN" + username.replace(/[^a-z\d\s]+/gi, "");
	options.user.username = options.user.username.substring(0, 18);

	var role = profile.userType;
	if (role != null && role != '') {
		if (role == "Student" || role == "student") {
			options.user.user_category = "student";
		} else if (role == "Faculty" || role == "faculty") {
			options.user.user_category = "teacher";
		} else {
			options.user.user_category = "other";
		}
	} else {
		options.user.user_category = "other";
	}

	new authenticate(req, res, options);

});

router.get('/generateMetadata', function(req, res) {
	res.type('application/xml');
	res.status(200).send(
			samlStrategy.generateServiceProviderMetadata(decryptionCert));

});

module.exports = router;
