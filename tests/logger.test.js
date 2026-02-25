// Mock winston and other dependencies before requiring the logger service
const mockWinston = {
    format: jest.fn((fn) => {
        const factory = jest.fn(() => ({
            transform: fn
        }));
        factory.combine = jest.fn();
        factory.timestamp = jest.fn();
        factory.errors = jest.fn();
        factory.printf = jest.fn();
        factory.colorize = jest.fn();
        return factory;
    }),
    transports: {
        Console: jest.fn()
    },
    createLogger: jest.fn(() => ({
        add: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
        audit: jest.fn()
    })),
    Transport: class {}
};

// Add combine etc to format itself since they are used as winston.format.combine
mockWinston.format.combine = jest.fn();
mockWinston.format.timestamp = jest.fn();
mockWinston.format.errors = jest.fn();
mockWinston.format.printf = jest.fn();
mockWinston.format.colorize = jest.fn();

jest.mock('winston', () => mockWinston, { virtual: true });
jest.mock('winston-daily-rotate-file', () => {
    return jest.fn().mockImplementation(() => ({}));
}, { virtual: true });

const { maskSensitiveData } = require('../services/logger');

describe('maskSensitiveData Winston Format', () => {
    const formatter = maskSensitiveData();

    test('masks top-level sensitive keys', () => {
        const info = {
            level: 'info',
            message: 'User login',
            password: 'secret123',
            token: 'abc-123'
        };
        const masked = formatter.transform(info);
        expect(masked.password).toBe('[MASKED]');
        expect(masked.token).toBe('[MASKED]');
        expect(masked.level).toBe('info');
        expect(masked.message).toBe('User login');
    });

    test('masks sensitive keys in nested objects', () => {
        const info = {
            level: 'info',
            message: 'API Request',
            details: {
                apiKey: 'super-secret',
                nested: {
                    credential: 'my-cred'
                },
                normal: 'value'
            }
        };
        const masked = formatter.transform(info);
        expect(masked.details.apiKey).toBe('[MASKED]');
        expect(masked.details.nested.credential).toBe('[MASKED]');
        expect(masked.details.normal).toBe('value');
    });

    test('masks sensitive keys in arrays', () => {
        const info = {
            level: 'info',
            data: [
                { id: 1, secret: 's1' },
                { id: 2, token: 't2' },
                'non-object'
            ]
        };
        const masked = formatter.transform(info);
        expect(masked.data[0].secret).toBe('[MASKED]');
        expect(masked.data[1].token).toBe('[MASKED]');
        expect(masked.data[2]).toBe('non-object');
    });

    test('handles case-insensitivity and partial matches', () => {
        const info = {
            PASSWORD: '123',
            user_token: 'abc',
            AuthorizationHeader: 'Bearer xyz'
        };
        const masked = formatter.transform(info);
        expect(masked.PASSWORD).toBe('[MASKED]');
        expect(masked.user_token).toBe('[MASKED]');
        expect(masked.AuthorizationHeader).toBe('[MASKED]');
    });

    test('does not mask Winston internal keys', () => {
        const info = {
            level: 'error',
            message: 'password failure', // message contains sensitive word but should not be masked
            timestamp: '2023-01-01',
            stack: 'Error: password wrong'
        };
        const masked = formatter.transform(info);
        expect(masked.level).toBe('error');
        expect(masked.message).toBe('password failure');
        expect(masked.timestamp).toBe('2023-01-01');
        expect(masked.stack).toBe('Error: password wrong');
    });

    test('handles circular references', () => {
        const info = {
            level: 'info',
            message: 'Circular test',
            meta: {}
        };
        info.meta.self = info.meta;

        const masked = formatter.transform(info);
        expect(masked.meta.self).toBe('[Circular]');
    });

    test('preserves Winston Symbols', () => {
        const LEVEL = Symbol.for('level');
        const SPLAT = Symbol.for('splat');
        const info = {
            message: 'test',
            password: 'secret'
        };
        info[LEVEL] = 'info';
        info[SPLAT] = ['arg1'];

        const masked = formatter.transform(info);
        expect(masked.password).toBe('[MASKED]');
        expect(masked[LEVEL]).toBe('info');
        expect(masked[SPLAT]).toEqual(['arg1']);
    });
});
