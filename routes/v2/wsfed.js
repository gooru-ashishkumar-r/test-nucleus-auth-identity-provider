var express = require('express');
var router = express.Router();
var passport = require('passport');
var config = require(process.env.CONFIG_FILE_PATH);
var logger = require('../../log');
var queryString = require('qs');
var superagent = require('superagent');
var WSFEDConfig = require('../../configuration/wsfedConfiguration');
var WSFEDConfiguration = new WSFEDConfig();

const configKeyPrefix = "WSFED-";

router.get('/login', function(req, res, next) {
    logger.info("Version 2 : Wsfed  signin entry point ...");
    const domain = req.hostname;

    if (typeof(domain) != 'undefined') {
        logger.info("searching for redirect Url for domain:" + domain);
		WSFEDConfiguration.getConfig(domain, function(err, strategy, wsfedConfig) {
		    if (!err) {
		        passport.use(getConfigStorageKey(domain), strategy);
		        passport.authenticate(getConfigStorageKey(domain), {
		            failureRedirect: '/',
		            failureFlash: true,
		            wctx: wsfedConfig.redirectURI
		        })(req, res, next);
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

router.post("/login", (req, res, next) => {
  logger.info("Processing POST Login request");
  const wctx = req.body.wctx;
  const requestBody = {};
  const redirectUrl = wctx;
  const domain = req.hostname;

  WSFEDConfiguration.getConfig(domain, function(err, strategy, wsfedConfig) {
  	passport.use(getConfigStorageKey(domain), strategy);

	passport.authenticate(getConfigStorageKey(domain), (err, profile, info) => {
    		requestBody.user = {};
    		requestBody.user.first_name = profile['http://identityserver.thinktecture.com/claims/profileclaims/firstname'];
    		requestBody.user.last_name =  profile['http://identityserver.thinktecture.com/claims/profileclaims/lastname'];

    		var role = profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'];
    		requestBody.grant_type = "wsfed";

		var account_id = profile['http://identityserver.thinktecture.com/claims/profileclaims/accountguid'];
		if (account_id != null) {
			requestBody.user.reference_id = account_id;
    		}

		var username = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'];
		if(username != null) {
        		requestBody.user.username = username;
    		}

    		var email = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'];
    		if (email != null) {
        		requestBody.user.email = email;
    		}

		const clientId = profile['http://gooru.org/tenant/clientid'];
		logger.info("client id received:" + clientId);
		WSFEDConfiguration.getSecret(clientId, function(err, secret) {
	  		if (!err) {
				logger.debug("got secret from database");
				const basicAuthToken = new Buffer((clientId + ":" + secret)).toString('base64');
				redirectUrl = (typeof(redirectUrl) === "undefined" || redirectUrl.length <= 0) ? wsfedConfig.homeRealm : redirectUrl;
        		authenticate(req, res, redirectUrl, requestBody, basicAuthToken);
	  		} else {
				logger.error("unable to get secret for the client:" + clientId);
				return next(err);
	  		}
		});
  	})(req, res, next)
  });
});


function authenticate(req, res, redirectUrl, requestBody, basicAuthToken) {
    superagent.post(config.authHandlerInternalHostName + '/api/internal/v2/sso/wsfed').send(requestBody).set('user-agent',req.headers['user-agent']).set('authorization', 'Basic ' + basicAuthToken).end(function(e, response) {
           var xForward = typeof(req.headers['x-forwarded-proto']) !== "undefined" ? req.headers['x-forwarded-proto'] : req.protocol;
            var domainName =  xForward  + '://' + config.domainName;
            if (!e && (response.status == 200 || response.status == 201)) {
                var json = JSON.parse(response.text);
                res.statusCode = 302;
                if (typeof(redirectUrl) === "undefined" || redirectUrl.length <= 0) {
                    redirectUrl = domainName;
                }
                redirectUrl += "?access_token=" + json.access_token;
                res.setHeader('Location', redirectUrl);
            } else {
                logger.error("V2 WSFED Authentication failure :");
                logger.error(response.text);
                res.statusCode = 302;
                res.setHeader('Location', domainName);
            }
            res.end();
     });

}

function getAppCredentials(request) {
   var reqparams = {};
   if (typeof(request.query.client_key) != 'undefined' && typeof(request.query.client_id) != 'undefined') {
       reqparams.client_id = request.query.client_id;
       reqparams.client_key = request.query.client_key;
   } else {
        // setting default value of Gooru Client key and Id, If client id and
		// key does not exist in request parameter
        reqparams.client_key = config.client_key;
        reqparams.client_id =  config.client_id;
   }
   return reqparams;
}

function getConfigStorageKey(id) {
    return configKeyPrefix + id;
}

module.exports = router;
