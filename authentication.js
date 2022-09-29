var express = require('express');
var bodyParser = require('body-parser');
var passport = require('passport');
var gmail = require('./routes/gmail');
var gmailv2 = require('./routes/v2/gmail');
var wsfed = require('./routes/wsfed');
var saml = require('./routes/saml');
var samlv2 = require('./routes/v2/saml');
var shibboleth = require('./routes/shibboleth');
var wsfedv2 = require('./routes/v2/wsfed');
var wsfedv3 = require('./routes/v3/wsfed');
var oauth2 = require('./routes/v1/oauth2');
var apple = require('./routes/v1/apple');
var xXssProtection = require('x-xss-protection');

var logger = require('./log');
var app = express();
app.use(xXssProtection());
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
	extended : false
}));
app.use(passport.initialize());
app.use(passport.session());
app.enable('trust proxy');
app.use('/api/nucleus-auth-idp/v1/google', gmail);
app.use('/api/nucleus-auth-idp/v2/google', gmailv2);
app.use('/api/nucleus-auth-idp/v1/wsfed', wsfed);
app.use('/api/nucleus-auth-idp/v1/saml', saml);
app.use('/api/nucleus-auth-idp/v1/shibboleth', shibboleth);
app.use('/api/nucleus-auth-idp/v2/wsfed', wsfedv2);
app.use('/api/nucleus-auth-idp/v3/wsfed', wsfedv3);
app.use('/api/nucleus-auth-idp/v1/oauth2', oauth2);
app.use('/api/nucleus-auth-idp/v1/apple', apple);
app.use('/api/nucleus-auth-idp/v2/saml', samlv2);



app.use(function(req, res, next) {
	var err = new Error('Not Found');
	err.status = 404;
	next(err);
});

app.use(function(err, req, res, next) {
	res.status(err.status || 500);
	logger.error("Error : ");
	logger.error(err);
	logger.error("request URL : " + req.url);
	if (err.status == 400 || err.status == 401 || err.status == 403) {
		res.end(err.message);
	} else {
		res.end("The application has encountered an unknown error.");
	}
});

module.exports = app;
