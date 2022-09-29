var config = require(process.env.CONFIG_FILE_PATH);
var extend = require('util')._extend;
var superagent = require('superagent');
var logger = require('../log');
var queryString = require('qs');

function authenticate(req, res, options) {
	var defaultOptions = {
		client_id : config.client_id,
		client_key : config.client_key
	};
	defaultOptions = extend(options, defaultOptions);
	var url = queryString.parse(req.headers.referer);
	var wreply = url['wreply'];
	superagent
			.post(config.hostname + '/api/nucleus-auth/v1/authorize')
			.send(defaultOptions)
			.set('user-agent', req.headers['user-agent'])
			.end(
					function(e, response) {
						var xForward = typeof (req.headers['x-forwarded-proto']) !== "undefined" ? req.headers['x-forwarded-proto']
								: req.protocol;
						var domainName = xForward + '://' + config.domainName;
						if (!e
								&& (response.status == 200 || response.status == 201)) {
							var json = JSON.parse(response.text);
							res.statusCode = 302;
							var redirectUrl = null;
							var callBackMethod = 'POST';
							if (req.query.state != null) {
								redirectUrl = req.query.state;
							} else if (typeof (wreply) !== "undefined"
									&& wreply.length > 0) {
								redirectUrl = wreply;
							} else {
								redirectUrl = domainName;
							}

							if (redirectUrl.indexOf("?") >= 0) {
								redirectUrl += "&access_token="
										+ json.access_token;
							} else {
								redirectUrl += "?access_token="
										+ json.access_token;
							}

							res.setHeader('Location', redirectUrl);
						} else {
							logger.error(" Authentication failure :");
							logger.error(response.text);
							res.statusCode = 302;
							res.setHeader('Location', domainName);
						}
						res.end();
					});

}
module.exports = authenticate;
