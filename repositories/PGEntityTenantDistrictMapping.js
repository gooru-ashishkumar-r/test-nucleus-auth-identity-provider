var DBTransaction = require('./DBTransaction');
var DBTransaction = new DBTransaction();

function PGEntityTenantDistrictMapping() {
};

const SELECT_BY_DISTRICT_ID = "SELECT tenant, secret from tenant_district_mapping WHERE district_id = $1::varchar";

PGEntityTenantDistrictMapping.prototype.getTenantMapping = function(params, callback) {
	DBTransaction
			.executeQuery(
					SELECT_BY_DISTRICT_ID,
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

module.exports = PGEntityTenantDistrictMapping;
