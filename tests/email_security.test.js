
const emailService = require('../services/emailService');
const nodemailer = require('nodemailer');

// Mock dependencies
jest.mock('nodemailer');
jest.mock('../config/database', () => ({
    getDatabase: jest.fn()
}));
jest.mock('../services/logger', () => ({
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn()
}));

describe('EmailService Security', () => {
    let sendMailMock;

    beforeEach(() => {
        jest.clearAllMocks();

        // Clear cached transporters to avoid test pollution
        if (emailService.transporters) {
            emailService.transporters.clear();
        }

        // Mock transporter
        sendMailMock = jest.fn().mockResolvedValue({ messageId: 'test-id' });
        nodemailer.createTransport.mockReturnValue({
            sendMail: sendMailMock,
            verify: jest.fn().mockResolvedValue(true)
        });

        const dbMock = {
            prepare: jest.fn().mockReturnValue({
                get: jest.fn().mockReturnValue({
                    email_enabled: 1,
                    email_address: 'test@example.com',
                    smtp_host: 'smtp.test',
                    smtp_port: 587,
                    smtp_secure: 0,
                    smtp_user: 'user',
                    smtp_pass: 'pass',
                    notify_critical_found: 1,
                    notify_scan_complete: 1
                }),
                run: jest.fn()
            })
        };
        require('../config/database').getDatabase.mockReturnValue(dbMock);
    });

    test('notifyCriticalFound should escape HTML in vulnerability details', async () => {
        const userId = 1;
        const scan = { id: 101, target: '<script>alert("scan")</script>' };
        const criticalVulns = [
            {
                ip_address: '192.168.1.1',
                port: 80,
                cve_id: '<img src=x onerror=alert(1)>',
                title: '<b>Bold Title</b>',
                cvss_score: '10.0'
            }
        ];

        await emailService.notifyCriticalFound(userId, scan, criticalVulns);

        expect(sendMailMock).toHaveBeenCalledTimes(1);
        const emailContent = sendMailMock.mock.calls[0][0].html;

        // Check that dangerous characters are escaped
        expect(emailContent).not.toContain('<script>alert("scan")</script>');
        expect(emailContent).toContain('&lt;script&gt;alert(&quot;scan&quot;)&lt;/script&gt;');

        expect(emailContent).not.toContain('<img src=x onerror=alert(1)>');
        expect(emailContent).toContain('&lt;img src=x onerror=alert(1)&gt;');

        expect(emailContent).not.toContain('<b>Bold Title</b>');
        expect(emailContent).toContain('&lt;b&gt;Bold Title&lt;/b&gt;');
    });

    test('notifyScanComplete should escape HTML in scan details', async () => {
        const userId = 2;
        const scan = {
            id: 102,
            target: '192.168.1.1" onmouseover="alert(1)',
            scan_type: '<script>bad()</script>'
        };
        const resultCount = 5;
        const vulnSummary = { total: 1, critical: 1, high: 0, medium: 0, low: 0 };

        await emailService.notifyScanComplete(userId, scan, resultCount, vulnSummary);

        expect(sendMailMock).toHaveBeenCalledTimes(1);
        const emailContent = sendMailMock.mock.calls[0][0].html;

        // Check that dangerous characters are escaped
        expect(emailContent).not.toContain('<script>bad()</script>');
        expect(emailContent).toContain('&lt;script&gt;bad()&lt;/script&gt;');

        expect(emailContent).not.toContain('192.168.1.1" onmouseover="alert(1)');
        expect(emailContent).toContain('192.168.1.1&quot; onmouseover=&quot;alert(1)');
    });
});
