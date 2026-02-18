const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');

const logDir = path.join(__dirname, '..', 'logs');

const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
        let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;
        if (stack) {
            log += `\n${stack}`;
        }
        if (Object.keys(meta).length > 0) {
            log += ` | ${JSON.stringify(meta)}`;
        }
        return log;
    })
);

const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({ format: 'HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message }) => {
        return `${timestamp} ${level}: ${message}`;
    })
);

// Daily rotate transport for general logs
const dailyRotateTransport = new DailyRotateFile({
    filename: path.join(logDir, 'securescope-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '30d',
    format: logFormat
});

// Daily rotate transport for error logs
const errorRotateTransport = new DailyRotateFile({
    filename: path.join(logDir, 'error-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '30d',
    level: 'error',
    format: logFormat
});

// Daily rotate transport for audit logs
const auditRotateTransport = new DailyRotateFile({
    filename: path.join(logDir, 'audit-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '90d',
    format: logFormat
});

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    transports: [
        dailyRotateTransport,
        errorRotateTransport
    ]
});

// Add console transport in development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: consoleFormat
    }));
}

// Create a separate audit logger
const auditLogger = winston.createLogger({
    level: 'info',
    format: logFormat,
    transports: [
        auditRotateTransport
    ]
});

if (process.env.NODE_ENV !== 'production') {
    auditLogger.add(new winston.transports.Console({
        format: consoleFormat
    }));
}

// Audit log helper
logger.audit = (action, details = {}) => {
    auditLogger.info(action, details);
};

module.exports = logger;