var DBTransaction = require('./DBTransaction');
var DBTransaction = new DBTransaction();

function PGEntityDomainBasedRedirect() {

};

const FETCH_REDIRECT_URL = "select redirect_url from domain_based_redirect where domain = $1::varchar";

PGEntityDomainBasedRedirect.prototype.getRedirectURL = function(params,
		callback) {
	DBTransaction
			.executeQuery(
					FETCH_REDIRECT_URL,
					params,
					function(err, res) {
						if (err) {
							callback(err, {});
						} else {
							var result = typeof (res.rows[0]) != 'undefined' ? res.rows[0]
									: {};
							callback(err, result);
						}
					});
};

module.exports = PGEntityDomainBasedRedirect;
