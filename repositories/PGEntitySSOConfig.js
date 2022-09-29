var DBTransaction = require('./DBTransaction');
var DBTransaction = new DBTransaction();

function PGEntitySSOConfig() {

};

const SELECT_SSO_CONFIG = "select config from sso_config where domain = $1::varchar AND sso_type= $2::varchar";
const SELECT_SSO_CONFIG_BY_TENANT = "select config, secret from sso_config where id = $1::uuid AND sso_type= $2::varchar";
const SELECT_SECRET = "select secret from sso_config where id = $1::uuid";
const SELECT_SSO_CONFIG_BY_SHORT_NAME = "select id, secret, config from sso_config where short_name = $1::varchar AND sso_type= $2::varchar";


PGEntitySSOConfig.prototype.getSSOConfig = function(params, callback) {
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

PGEntitySSOConfig.prototype.getSSOConfigByTenant = function(params, callback) {
	DBTransaction
			.executeQuery(
					SELECT_SSO_CONFIG_BY_TENANT,
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

PGEntitySSOConfig.prototype.getSecret = function(params, callback) {
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

PGEntitySSOConfig.prototype.getSSOConfigByShortname = function(params, callback) {
	DBTransaction
			.executeQuery(
					SELECT_SSO_CONFIG_BY_SHORT_NAME,
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

module.exports = PGEntitySSOConfig;
