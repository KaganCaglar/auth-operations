const winston = require('winston');
const path = require('path');

// Log dosyasının yolu
const logFilePath = path.join(__dirname, 'logfile.log');

// Logger oluştur
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: logFilePath }),
  ],
  format: winston.format.combine(winston.format.timestamp(), winston.format.simple()),
});

// Export the logger
module.exports = logger;
