const logStreamService = require('../services/logStreamService');

describe('Log Streaming Logic', () => {
    test('broadcasts correct data structure', () => {
        const mockRes = {
            write: jest.fn()
        };
        logStreamService.addClient(mockRes);

        // Simulate info object from winston
        const info = {
            level: 'info',
            message: 'User logged in',
            timestamp: '2023-10-27T10:00:00.000Z',
            userId: 123,
            ip: '127.0.0.1'
        };

        logStreamService.broadcast(info);

        expect(mockRes.write).toHaveBeenCalled();
        const dataStr = mockRes.write.mock.calls[0][0];

        // Parse the data payload
        const jsonStr = dataStr.replace('data: ', '').trim();
        const entry = JSON.parse(jsonStr);

        expect(entry.level).toBe('info');
        expect(entry.message).toBe('User logged in');

        // We expect metadata to be captured correctly
        expect(entry.meta).toEqual({
            userId: 123,
            ip: '127.0.0.1'
        });
    });
});
