var winston = require('winston');
require('winston-daily-rotate-file');
var config = require(process.env.CONFIG_FILE_PATH);
var transport = new (winston.transports.DailyRotateFile)({
	filename : config.appConfiguration.loggerFilePath,
	datePattern : 'nucleus_idp_error-yyyy-MM-dd.',
	prepend : true,
	level : 'error'
});

var logger = new (winston.Logger)({
	transports : [ transport ]
});

module.exports = logger;
