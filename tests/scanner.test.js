
// Mock dependencies before requiring ScannerService
jest.mock('ip-cidr', () => {
    const mockIPCIDR = jest.fn().mockImplementation((cidr) => {
        if (!cidr || typeof cidr !== 'string' || cidr === 'invalid' || cidr.includes('error')) {
            throw new Error('Invalid CIDR');
        }
        return {
            toArray: () => {
                if (cidr === '192.168.1.0/24' || cidr === '192.168.1.5/24') {
                    return Array.from({ length: 256 }, (_, i) => `192.168.1.${i}`);
                }
                if (cidr === '192.168.1.1/32') {
                    return ['192.168.1.1'];
                }
                if (cidr === '10.0.0.0/31') {
                    return ['10.0.0.0', '10.0.0.1'];
                }
                return [];
            }
        };
    });

    mockIPCIDR.isValidCIDR = jest.fn().mockImplementation((cidr) => {
        return typeof cidr === 'string' && cidr.includes('/') && !cidr.includes('invalid');
    });

    return {
        default: mockIPCIDR,
        isValidCIDR: mockIPCIDR.isValidCIDR
    };
});

jest.mock('../config/database', () => ({
    getDatabase: jest.fn()
}));

jest.mock('../services/logger', () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    audit: jest.fn()
}));

jest.mock('../services/exploitService', () => ({}));
jest.mock('../services/emailService', () => ({}));
jest.mock('../services/nmapParser', () => ({}));
jest.mock('../services/cveService', () => ({}));

// Now require ScannerService
const scannerService = require('../services/scanner');

describe('ScannerService Static Methods', () => {
    describe('expandCIDR', () => {
        test('should expand a valid /24 CIDR', () => {
            const ips = scannerService.constructor.expandCIDR('192.168.1.0/24');
            expect(ips).toHaveLength(256);
            expect(ips[0]).toBe('192.168.1.0');
            expect(ips[255]).toBe('192.168.1.255');
        });

        test('should handle CIDR with non-zero host bits', () => {
            const ips = scannerService.constructor.expandCIDR('192.168.1.5/24');
            expect(ips).toHaveLength(256);
            expect(ips[0]).toBe('192.168.1.0');
        });

        test('should expand a /32 CIDR (single IP)', () => {
            const ips = scannerService.constructor.expandCIDR('192.168.1.1/32');
            expect(ips).toEqual(['192.168.1.1']);
        });

        test('should expand a /31 CIDR', () => {
            const ips = scannerService.constructor.expandCIDR('10.0.0.0/31');
            expect(ips).toEqual(['10.0.0.0', '10.0.0.1']);
        });

        test('should return empty array for invalid CIDR string', () => {
            const ips = scannerService.constructor.expandCIDR('invalid');
            expect(ips).toEqual([]);
        });

        test('should return empty array for CIDR that causes library error', () => {
            const ips = scannerService.constructor.expandCIDR('cause-error/24');
            expect(ips).toEqual([]);
        });

        test('should return empty array for null/undefined/non-string', () => {
            expect(scannerService.constructor.expandCIDR(null)).toEqual([]);
            expect(scannerService.constructor.expandCIDR(undefined)).toEqual([]);
            expect(scannerService.constructor.expandCIDR(123)).toEqual([]);
            expect(scannerService.constructor.expandCIDR({})).toEqual([]);
        });
    });

    describe('isValidIP', () => {
        test('should validate correct IPv4 addresses', () => {
            expect(scannerService.constructor.isValidIP('192.168.1.1')).toBe(true);
            expect(scannerService.constructor.isValidIP('10.0.0.1')).toBe(true);
            expect(scannerService.constructor.isValidIP('172.16.0.1')).toBe(true);
        });

        test('should reject incorrect IPv4 addresses', () => {
            expect(scannerService.constructor.isValidIP('256.256.256.256')).toBe(false);
            expect(scannerService.constructor.isValidIP('192.168.1')).toBe(false);
            expect(scannerService.constructor.isValidIP('abc.def.ghi.jkl')).toBe(false);
            expect(scannerService.constructor.isValidIP('')).toBe(false);
            expect(scannerService.constructor.isValidIP('127.0.0.0.1')).toBe(false);
        });
    });

    describe('isPrivateIP', () => {
        test('should identify RFC 1918 private addresses', () => {
            expect(scannerService.constructor.isPrivateIP('10.0.0.1')).toBe(true);
            expect(scannerService.constructor.isPrivateIP('172.16.0.1')).toBe(true);
            expect(scannerService.constructor.isPrivateIP('172.31.255.255')).toBe(true);
            expect(scannerService.constructor.isPrivateIP('192.168.1.1')).toBe(true);
            expect(scannerService.constructor.isPrivateIP('127.0.0.1')).toBe(true);
        });

        test('should identify public addresses', () => {
            expect(scannerService.constructor.isPrivateIP('8.8.8.8')).toBe(false);
            expect(scannerService.constructor.isPrivateIP('1.1.1.1')).toBe(false);
            expect(scannerService.constructor.isPrivateIP('172.15.255.255')).toBe(false);
            expect(scannerService.constructor.isPrivateIP('172.32.0.0')).toBe(false);
        });
    });

    describe('validateTarget', () => {
        test('should validate single IP target', () => {
            const result = scannerService.constructor.validateTarget('192.168.1.1');
            expect(result.valid).toBe(true);
            expect(result.type).toBe('single');
            expect(result.target).toBe('192.168.1.1');
        });

        test('should validate valid CIDR target', () => {
            const result = scannerService.constructor.validateTarget('192.168.1.0/24');
            expect(result.valid).toBe(true);
            expect(result.type).toBe('cidr');
        });

        test('should reject CIDR larger than /24', () => {
            const result = scannerService.constructor.validateTarget('192.168.1.0/23');
            expect(result.valid).toBe(false);
            expect(result.error).toContain('Maximal /24');
        });

        test('should reject malformed targets', () => {
            expect(scannerService.constructor.validateTarget('invalid').valid).toBe(false);
            expect(scannerService.constructor.validateTarget('192.168.1.256').valid).toBe(false);
        });
    });

    describe('validatePorts', () => {
        test('should validate single port', () => {
            expect(scannerService.constructor.validatePorts('80').valid).toBe(true);
        });

        test('should validate port range', () => {
            expect(scannerService.constructor.validatePorts('1-1024').valid).toBe(true);
        });

        test('should validate comma-separated ports', () => {
            expect(scannerService.constructor.validatePorts('80,443,8080').valid).toBe(true);
        });

        test('should reject invalid port numbers', () => {
            expect(scannerService.constructor.validatePorts('0').valid).toBe(false);
            expect(scannerService.constructor.validatePorts('65536').valid).toBe(false);
            expect(scannerService.constructor.validatePorts('abc').valid).toBe(false);
        });

        test('should reject invalid port ranges', () => {
            expect(scannerService.constructor.validatePorts('1000-500').valid).toBe(false);
            expect(scannerService.constructor.validatePorts('1-70000').valid).toBe(false);
            expect(scannerService.constructor.validatePorts('80-abc').valid).toBe(false);
        });
    });
});
