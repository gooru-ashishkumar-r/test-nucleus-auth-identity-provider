var DBConnection = require('./DBConnection');
function DBTransaction() {

};

DBTransaction.prototype.executeQuery = function(sql, params, callback) {
	DBConnection.query(sql, params, function(err, res) {
		callback(err, res);
	});
};

module.exports = DBTransaction;
