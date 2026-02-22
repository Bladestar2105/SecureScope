const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const Transport = winston.transport;
const logStreamService = require('./logStreamService');

const logDir = path.join(__dirname, '..', 'logs');

// Sensitive keys to mask in logs
const SENSITIVE_KEYS = [
    'password', 'passwd', 'token', 'secret', 'authorization',
    'cookie', 'session', 'passphrase', 'apikey', 'credential'
];

// Winston internal keys that should not be masked
const IGNORED_KEYS = ['level', 'message', 'timestamp', 'stack'];

// Custom format to mask sensitive data in metadata
const maskSensitiveData = winston.format((info) => {
    const seen = new WeakMap();

    const mask = (val, key) => {
        // Mask sensitive keys (except internal winston keys)
        if (key && typeof key === 'string' && !IGNORED_KEYS.includes(key)) {
            const isSensitive = SENSITIVE_KEYS.some(sk =>
                key.toLowerCase().includes(sk)
            );
            if (isSensitive) return '[MASKED]';
        }

        // Only recurse into objects and arrays
        if (typeof val !== 'object' || val === null) return val;

        // Handle circular references
        if (seen.has(val)) return '[Circular]';
        seen.set(val, true);

        if (Array.isArray(val)) {
            return val.map(item => mask(item));
        }

        const cloned = {};
        for (const k in val) {
            if (Object.prototype.hasOwnProperty.call(val, k)) {
                cloned[k] = mask(val[k], k);
            }
        }
        return cloned;
    };

    return mask(info);
});

const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    maskSensitiveData(),
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
    maskSensitiveData(),
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

// Custom Transport for Web UI Streaming
class WebStreamTransport extends Transport {
    constructor(opts) {
        super(opts);
    }

    log(info, callback) {
        setImmediate(() => {
            this.emit('logged', info);
        });

        // Broadcast to SSE clients via service
        logStreamService.broadcast(info);

        callback();
    }
}

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    transports: [
        dailyRotateTransport,
        errorRotateTransport,
        new WebStreamTransport()
    ]
});

// Always add console transport (needed for Docker logs)
logger.add(new winston.transports.Console({
    format: consoleFormat
}));

// Create a separate audit logger
const auditLogger = winston.createLogger({
    level: 'info',
    format: logFormat,
    transports: [
        auditRotateTransport
    ]
});

// Always log audits to console
auditLogger.add(new winston.transports.Console({
    format: consoleFormat
}));

// Audit log helper
logger.audit = (action, details = {}) => {
    auditLogger.info(action, details);
};

module.exports = logger;