const { getDatabase } = require('../config/database');
const FingerprintService = require('../services/fingerprintService');

jest.mock('../config/database', () => ({
    getDatabase: jest.fn()
}));

jest.mock('../services/logger', () => ({
    info: jest.fn()
}));

describe('FingerprintService Optimization', () => {
    let mockDb;

    beforeEach(() => {
        jest.clearAllMocks();
        mockDb = {
            prepare: jest.fn(),
            transaction: jest.fn(fn => fn)
        };
        getDatabase.mockReturnValue(mockDb);
    });

    test('matchScanResults should batch fingerprint queries and use Map for lookup', () => {
        const scanId = 1;
        const scanResults = [
            { id: 101, port: 80, ip_address: '1.1.1.1' },
            { id: 102, port: 443, ip_address: '1.1.1.1' },
            { id: 103, port: 80, ip_address: '1.1.1.2' }
        ];

        const fingerprints = [
            { id: 1, port: 80, service_name: 'http', confidence: 90 },
            { id: 2, port: 443, service_name: 'https', confidence: 85 }
        ];

        const mockPrepare = jest.fn();
        mockDb.prepare = mockPrepare;

        // 1. Fetch scan results
        mockPrepare.mockReturnValueOnce({
            all: jest.fn().mockReturnValue(scanResults)
        });

        // 2. Prepare insert statement
        const mockInsertStmt = { run: jest.fn() };
        mockPrepare.mockReturnValueOnce(mockInsertStmt);

        // 3. Fetch all fingerprints in batch
        mockPrepare.mockReturnValueOnce({
            all: jest.fn().mockReturnValue(fingerprints)
        });

        const results = FingerprintService.matchScanResults(scanId);

        // Verification
        expect(mockPrepare).toHaveBeenCalledTimes(3);

        // Check scan results query
        expect(mockPrepare.mock.calls[0][0]).toContain('SELECT * FROM scan_results');

        // Check insert statement preparation
        expect(mockPrepare.mock.calls[1][0]).toContain('INSERT INTO scan_fingerprints');

        // Check batch fingerprint query
        expect(mockPrepare.mock.calls[2][0]).toContain('SELECT * FROM fingerprints WHERE port IN (?,?)');

        // Verify the batch query was called with unique ports
        const batchQueryMock = mockPrepare.mock.results[2].value.all;
        expect(batchQueryMock).toHaveBeenCalledWith(80, 443);

        // Verify results
        expect(results).toHaveLength(3);
        expect(results[0].port).toBe(80);
        expect(results[0].service).toBe('http');
        expect(results[1].port).toBe(443);
        expect(results[1].service).toBe('https');
        expect(results[2].port).toBe(80);
        expect(results[2].service).toBe('http');

        // Verify insertStmt.run was called for each result
        expect(mockInsertStmt.run).toHaveBeenCalledTimes(3);
    });

    test('matchScanResults should handle no scan results', () => {
        mockDb.prepare.mockReturnValueOnce({
            all: jest.fn().mockReturnValue([])
        });

        const results = FingerprintService.matchScanResults(1);
        expect(results).toEqual([]);
        expect(mockDb.prepare).toHaveBeenCalledTimes(1);
    });

    test('matchScanResults should handle no matching fingerprints', () => {
        const scanResults = [{ id: 101, port: 999, ip_address: '1.1.1.1' }];

        mockDb.prepare.mockReturnValueOnce({
            all: jest.fn().mockReturnValue(scanResults)
        });
        mockDb.prepare.mockReturnValueOnce({ run: jest.fn() }); // insertStmt
        mockDb.prepare.mockReturnValueOnce({
            all: jest.fn().mockReturnValue([]) // no fingerprints
        });

        const results = FingerprintService.matchScanResults(1);
        expect(results).toEqual([]);
        expect(mockDb.prepare).toHaveBeenCalledTimes(3);
    });

    test('matchScanResults should chunk batch queries when there are many unique ports', () => {
        const scanResults = [];
        for (let i = 0; i < 1000; i++) {
            scanResults.push({ id: i, port: i, ip_address: '1.1.1.1' });
        }

        const mockPrepare = jest.fn();
        mockDb.prepare = mockPrepare;

        // 1. Fetch scan results
        mockPrepare.mockReturnValueOnce({
            all: jest.fn().mockReturnValue(scanResults)
        });

        // 2. Prepare insert statement
        mockPrepare.mockReturnValueOnce({ run: jest.fn() });

        // 3. First chunk (900 ports)
        mockPrepare.mockReturnValueOnce({
            all: jest.fn().mockReturnValue([])
        });

        // 4. Second chunk (100 ports)
        mockPrepare.mockReturnValueOnce({
            all: jest.fn().mockReturnValue([])
        });

        FingerprintService.matchScanResults(1);

        // Verify it was prepared 1 (results) + 1 (insert) + 2 (chunks) = 4 times
        expect(mockPrepare).toHaveBeenCalledTimes(4);

        // Check chunk 1 (900 placeholders)
        const placeholders1 = Array(900).fill('?').join(',');
        expect(mockPrepare.mock.calls[2][0]).toContain(`port IN (${placeholders1})`);

        // Check chunk 2 (100 placeholders)
        const placeholders2 = Array(100).fill('?').join(',');
        expect(mockPrepare.mock.calls[3][0]).toContain(`port IN (${placeholders2})`);
    });
});
