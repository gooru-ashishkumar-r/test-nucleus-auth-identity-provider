var DBTransaction = require('../../repositories/DBTransaction');
var DBTransaction = new DBTransaction();

function PGEntitySSOConfigV3() {
};

const SELECT_SSO_CONFIG = "SELECT config FROM sso_config WHERE short_name = $1::varchar AND sso_type= $2::varchar";
const SELECT_SECRET = "SELECT secret FROM sso_config WHERE id = $1::uuid";

PGEntitySSOConfigV3.prototype.getSSOConfig = function(params, callback) {
	DBTransaction
			.executeQuery(
					SELECT_SSO_CONFIG,
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

PGEntitySSOConfigV3.prototype.getSecret = function(params, callback) {
	DBTransaction
			.executeQuery(
					SELECT_SECRET,
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

module.exports = PGEntitySSOConfigV3;
