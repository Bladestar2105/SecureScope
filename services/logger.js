const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const Transport = winston.Transport;
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
// IMPORTANT: Winston requires Symbol.for('level') and Symbol.for('splat') on the info object.
// We must mutate in-place or copy Symbols when cloning, otherwise the pipeline silently drops messages.
const maskSensitiveData = winston.format((info) => {
    const seen = new WeakSet();

    const maskValue = (val, key) => {
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
        seen.add(val);

        if (Array.isArray(val)) {
            return val.map(item => maskValue(item));
        }

        // For nested objects (not the top-level info), clone them
        const cloned = {};
        for (const k in val) {
            if (Object.prototype.hasOwnProperty.call(val, k)) {
                cloned[k] = maskValue(val[k], k);
            }
        }
        return cloned;
    };

    // Mask sensitive values in-place on the info object to preserve Winston Symbols
    for (const key of Object.keys(info)) {
        if (IGNORED_KEYS.includes(key)) continue;
        info[key] = maskValue(info[key], key);
    }

    return info;
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