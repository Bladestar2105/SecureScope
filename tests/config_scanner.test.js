const scannerConfig = require('../config/scanner');

describe('Scanner Configuration', () => {
    test('should have TOP_100_PORTS defined as a string', () => {
        expect(typeof scannerConfig.TOP_100_PORTS).toBe('string');
        expect(scannerConfig.TOP_100_PORTS.length).toBeGreaterThan(0);
        expect(scannerConfig.TOP_100_PORTS).toContain('80,81,88');
    });

    test('should have TOP_1000_PORTS defined as a string', () => {
        expect(typeof scannerConfig.TOP_1000_PORTS).toBe('string');
        expect(scannerConfig.TOP_1000_PORTS.length).toBeGreaterThan(0);
        expect(scannerConfig.TOP_1000_PORTS).toContain('1-1024');
    });

    test('should have FULL_PORT_RANGE defined as 1-65535', () => {
        expect(scannerConfig.FULL_PORT_RANGE).toBe('1-65535');
    });

    test('should have DEFAULT_MAX_CONCURRENT defined as 3', () => {
        expect(scannerConfig.DEFAULT_MAX_CONCURRENT).toBe(3);
    });

    test('should have DEFAULT_SCAN_TIMEOUT defined as 600000', () => {
        expect(scannerConfig.DEFAULT_SCAN_TIMEOUT).toBe(600000);
    });
});
