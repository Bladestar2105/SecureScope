const express = require('express');
const router = express.Router();
const emailService = require('../services/emailService');
const EmailService = require('../services/emailService');
const { requireAuth } = require('../middleware/auth');
const logger = require('../services/logger');
const crypto = require('crypto');
const { CREDENTIAL_SECRET, CREDENTIAL_SALT } = require('../config/security');

// Encryption helpers for SMTP password
const SMTP_ENCRYPTION_KEY = crypto.scryptSync(CREDENTIAL_SECRET, CREDENTIAL_SALT, 32);
const SMTP_IV_LENGTH = 16;
const SMTP_ALGORITHM = 'aes-256-gcm';

function encryptSmtpPass(text) {
    if (!text) return null;
    const iv = crypto.randomBytes(SMTP_IV_LENGTH);
    const cipher = crypto.createCipheriv(SMTP_ALGORITHM, SMTP_ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decryptSmtpPass(encryptedText) {
    if (!encryptedText) return null;
    try {
        const parts = encryptedText.split(':');
        if (parts.length !== 3) return encryptedText; // Legacy plaintext fallback
        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const encrypted = parts[2];
        const decipher = crypto.createDecipheriv(SMTP_ALGORITHM, SMTP_ENCRYPTION_KEY, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (err) {
        return encryptedText; // Legacy plaintext fallback
    }
}

router.use(requireAuth);

// GET /api/notifications/settings - Get notification settings
router.get('/settings', (req, res) => {
    try {
        const settings = EmailService.constructor.getSettings
            ? EmailService.constructor.getSettings(req.session.userId)
            : require('../services/emailService').constructor.getSettings
                ? require('../services/emailService').constructor.getSettings(req.session.userId)
                : null;

        // Use the static method from the class
        const EmailServiceClass = require('../services/emailService').constructor;
        const db = require('../config/database').getDatabase();
        const dbSettings = db.prepare('SELECT * FROM notification_settings WHERE user_id = ?').get(req.session.userId);

        if (!dbSettings) {
            return res.json({
                settings: {
                    emailEnabled: false,
                    emailAddress: '',
                    smtpHost: '',
                    smtpPort: 587,
                    smtpSecure: false,
                    smtpUser: '',
                    notifyScanComplete: true,
                    notifyCriticalFound: true,
                    notifyScheduledReport: true
                }
            });
        }

        res.json({
            settings: {
                emailEnabled: dbSettings.email_enabled === 1,
                emailAddress: dbSettings.email_address || '',
                smtpHost: dbSettings.smtp_host || '',
                smtpPort: dbSettings.smtp_port || 587,
                smtpSecure: dbSettings.smtp_secure === 1,
                smtpUser: dbSettings.smtp_user || '',
                smtpPassSet: !!dbSettings.smtp_pass,
                notifyScanComplete: dbSettings.notify_scan_complete === 1,
                notifyCriticalFound: dbSettings.notify_critical_found === 1,
                notifyScheduledReport: dbSettings.notify_scheduled_report === 1
            }
        });
    } catch (err) {
        logger.error('Notification settings get error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// POST /api/notifications/settings - Save notification settings
router.post('/settings', (req, res) => {
    try {
        const {
            emailEnabled, emailAddress, smtpHost, smtpPort, smtpSecure,
            smtpUser, smtpPass, notifyScanComplete, notifyCriticalFound, notifyScheduledReport
        } = req.body;

        // Validate email if enabled
        if (emailEnabled && emailAddress) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(emailAddress)) {
                return res.status(400).json({ error: 'Ungültige E-Mail-Adresse' });
            }
        }

        if (emailEnabled && !smtpHost) {
            return res.status(400).json({ error: 'SMTP-Host ist erforderlich wenn E-Mail aktiviert ist' });
        }

        // Use the static method
        const { getDatabase } = require('../config/database');
        const db = getDatabase();
        const existing = db.prepare('SELECT id FROM notification_settings WHERE user_id = ?').get(req.session.userId);

        if (existing) {
            const updateFields = [
                'email_enabled = ?', 'email_address = ?', 'smtp_host = ?',
                'smtp_port = ?', 'smtp_secure = ?', 'smtp_user = ?',
                'notify_scan_complete = ?', 'notify_critical_found = ?',
                'notify_scheduled_report = ?', 'updated_at = CURRENT_TIMESTAMP'
            ];
            const params = [
                emailEnabled ? 1 : 0, emailAddress || null, smtpHost || null,
                smtpPort || 587, smtpSecure ? 1 : 0, smtpUser || null,
                notifyScanComplete !== false ? 1 : 0, notifyCriticalFound !== false ? 1 : 0,
                notifyScheduledReport !== false ? 1 : 0
            ];

            // Only update password if provided (encrypt it)
            if (smtpPass && smtpPass.length > 0) {
                updateFields.splice(6, 0, 'smtp_pass = ?');
                params.splice(6, 0, encryptSmtpPass(smtpPass));
            }

            params.push(req.session.userId);
            db.prepare(`UPDATE notification_settings SET ${updateFields.join(', ')} WHERE user_id = ?`).run(...params);
        } else {
            db.prepare(`
                INSERT INTO notification_settings 
                (user_id, email_enabled, email_address, smtp_host, smtp_port, smtp_secure, 
                 smtp_user, smtp_pass, notify_scan_complete, notify_critical_found, notify_scheduled_report)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                req.session.userId,
                emailEnabled ? 1 : 0, emailAddress || null, smtpHost || null,
                smtpPort || 587, smtpSecure ? 1 : 0, smtpUser || null, smtpPass ? encryptSmtpPass(smtpPass) : null,
                notifyScanComplete !== false ? 1 : 0, notifyCriticalFound !== false ? 1 : 0,
                notifyScheduledReport !== false ? 1 : 0
            );
        }

        // Clear cached transporter
        emailService.transporters.delete(req.session.userId);

        logger.info(`Notification settings saved for user ${req.session.userId}`);
        res.json({ success: true, message: 'Benachrichtigungseinstellungen gespeichert' });
    } catch (err) {
        logger.error('Notification settings save error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// POST /api/notifications/test - Send test email
router.post('/test', async (req, res) => {
    try {
        // First verify connection
        await emailService.testConnection(req.session.userId);

        // Send test email
        const sent = await emailService.sendEmail(
            req.session.userId,
            'Test-Benachrichtigung',
            `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #3b82f6, #8b5cf6); padding: 20px; border-radius: 8px 8px 0 0;">
                    <h1 style="color: white; margin: 0; font-size: 20px;">🛡️ SecureScope - Test</h1>
                </div>
                <div style="background: #1a2234; color: #e2e8f0; padding: 20px; border-radius: 0 0 8px 8px;">
                    <p>Dies ist eine Test-E-Mail von SecureScope.</p>
                    <p style="color: #10b981;">✅ E-Mail-Benachrichtigungen funktionieren korrekt!</p>
                    <p style="color: #64748b; font-size: 12px; margin-top: 20px;">
                        Gesendet am: ${new Date().toLocaleString('de-DE')}
                    </p>
                </div>
            </div>`
        );

        if (sent) {
            res.json({ success: true, message: 'Test-E-Mail wurde gesendet' });
        } else {
            res.status(500).json({ error: 'E-Mail konnte nicht gesendet werden' });
        }
    } catch (err) {
        logger.error('Test email error:', err);
        res.status(400).json({ error: err.message });
    }
});

module.exports = router;