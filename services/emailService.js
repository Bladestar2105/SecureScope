const nodemailer = require('nodemailer');
const { getDatabase } = require('../config/database');
const logger = require('./logger');

class EmailService {
    constructor() {
        this.transporters = new Map(); // userId -> transporter
    }

    // Get notification settings for a user
    static getSettings(userId) {
        const db = getDatabase();
        return db.prepare('SELECT * FROM notification_settings WHERE user_id = ?').get(userId);
    }

    // Save notification settings
    static saveSettings(userId, settings) {
        const db = getDatabase();
        const existing = db.prepare('SELECT id FROM notification_settings WHERE user_id = ?').get(userId);

        if (existing) {
            db.prepare(`
                UPDATE notification_settings SET
                    email_enabled = ?,
                    email_address = ?,
                    smtp_host = ?,
                    smtp_port = ?,
                    smtp_secure = ?,
                    smtp_user = ?,
                    smtp_pass = CASE WHEN ? IS NOT NULL AND ? != '' THEN ? ELSE smtp_pass END,
                    notify_scan_complete = ?,
                    notify_critical_found = ?,
                    notify_scheduled_report = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            `).run(
                settings.emailEnabled ? 1 : 0,
                settings.emailAddress || null,
                settings.smtpHost || null,
                settings.smtpPort || 587,
                settings.smtpSecure ? 1 : 0,
                settings.smtpUser || null,
                settings.smtpPass, settings.smtpPass, settings.smtpPass || null,
                settings.notifyScanComplete !== false ? 1 : 0,
                settings.notifyCriticalFound !== false ? 1 : 0,
                settings.notifyScheduledReport !== false ? 1 : 0,
                userId
            );
        } else {
            db.prepare(`
                INSERT INTO notification_settings 
                (user_id, email_enabled, email_address, smtp_host, smtp_port, smtp_secure, 
                 smtp_user, smtp_pass, notify_scan_complete, notify_critical_found, notify_scheduled_report)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                userId,
                settings.emailEnabled ? 1 : 0,
                settings.emailAddress || null,
                settings.smtpHost || null,
                settings.smtpPort || 587,
                settings.smtpSecure ? 1 : 0,
                settings.smtpUser || null,
                settings.smtpPass || null,
                settings.notifyScanComplete !== false ? 1 : 0,
                settings.notifyCriticalFound !== false ? 1 : 0,
                settings.notifyScheduledReport !== false ? 1 : 0
            );
        }

        // Clear cached transporter
        emailServiceInstance.transporters.delete(userId);

        logger.info(`Notification settings updated for user ${userId}`);
    }

    // Create or get SMTP transporter for a user
    _getTransporter(userId) {
        if (this.transporters.has(userId)) {
            return this.transporters.get(userId);
        }

        const settings = EmailService.getSettings(userId);
        if (!settings || !settings.email_enabled || !settings.smtp_host) {
            return null;
        }

        const transporter = nodemailer.createTransport({
            host: settings.smtp_host,
            port: settings.smtp_port || 587,
            secure: settings.smtp_secure === 1,
            auth: settings.smtp_user ? {
                user: settings.smtp_user,
                pass: settings.smtp_pass
            } : undefined,
            tls: {
                rejectUnauthorized: false
            }
        });

        this.transporters.set(userId, transporter);
        return transporter;
    }

    // Send email to a user
    async sendEmail(userId, subject, htmlContent, textContent) {
        const settings = EmailService.getSettings(userId);
        if (!settings || !settings.email_enabled || !settings.email_address) {
            logger.debug(`Email not sent to user ${userId}: notifications disabled or no email configured`);
            return false;
        }

        const transporter = this._getTransporter(userId);
        if (!transporter) {
            logger.warn(`No SMTP transporter available for user ${userId}`);
            return false;
        }

        try {
            const info = await transporter.sendMail({
                from: settings.smtp_user || `securescope@${settings.smtp_host}`,
                to: settings.email_address,
                subject: `[SecureScope] ${subject}`,
                html: htmlContent,
                text: textContent || htmlContent.replace(/<[^>]*>/g, '')
            });

            logger.info(`Email sent to user ${userId}: ${subject} (${info.messageId})`);
            return true;
        } catch (err) {
            logger.error(`Failed to send email to user ${userId}:`, err);
            return false;
        }
    }

    // Test SMTP connection
    async testConnection(userId) {
        const transporter = this._getTransporter(userId);
        if (!transporter) {
            throw new Error('SMTP nicht konfiguriert');
        }

        try {
            await transporter.verify();
            return true;
        } catch (err) {
            throw new Error(`SMTP-Verbindung fehlgeschlagen: ${err.message}`);
        }
    }

    // Send scan completion notification
    async notifyScanComplete(userId, scan, resultCount, vulnSummary) {
        const settings = EmailService.getSettings(userId);
        if (!settings || !settings.notify_scan_complete) return;

        const subject = `Scan #${scan.id} abgeschlossen - ${resultCount} offene Ports`;

        const html = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #3b82f6, #8b5cf6); padding: 20px; border-radius: 8px 8px 0 0;">
                    <h1 style="color: white; margin: 0; font-size: 20px;">🛡️ SecureScope - Scan abgeschlossen</h1>
                </div>
                <div style="background: #1a2234; color: #e2e8f0; padding: 20px; border-radius: 0 0 8px 8px;">
                    <h2 style="color: #3b82f6; font-size: 16px;">Scan #${scan.id} - ${scan.target}</h2>
                    <table style="width: 100%; border-collapse: collapse; margin: 15px 0;">
                        <tr><td style="padding: 8px; color: #94a3b8;">Ziel:</td><td style="padding: 8px;">${scan.target}</td></tr>
                        <tr><td style="padding: 8px; color: #94a3b8;">Typ:</td><td style="padding: 8px;">${scan.scan_type}</td></tr>
                        <tr><td style="padding: 8px; color: #94a3b8;">Status:</td><td style="padding: 8px; color: #10b981;">Abgeschlossen</td></tr>
                        <tr><td style="padding: 8px; color: #94a3b8;">Offene Ports:</td><td style="padding: 8px; font-weight: bold;">${resultCount}</td></tr>
                    </table>
                    ${vulnSummary && vulnSummary.total > 0 ? `
                    <div style="background: #0f1623; padding: 15px; border-radius: 6px; margin-top: 15px;">
                        <h3 style="color: #f59e0b; font-size: 14px; margin-top: 0;">⚠️ Schwachstellen gefunden</h3>
                        <p style="margin: 5px 0;"><span style="color: #ef4444;">Kritisch: ${vulnSummary.critical || 0}</span></p>
                        <p style="margin: 5px 0;"><span style="color: #f59e0b;">Hoch: ${vulnSummary.high || 0}</span></p>
                        <p style="margin: 5px 0;"><span style="color: #eab308;">Mittel: ${vulnSummary.medium || 0}</span></p>
                        <p style="margin: 5px 0;"><span style="color: #10b981;">Niedrig: ${vulnSummary.low || 0}</span></p>
                    </div>
                    ` : ''}
                    <p style="color: #64748b; font-size: 12px; margin-top: 20px;">
                        Diese E-Mail wurde automatisch von SecureScope generiert.
                    </p>
                </div>
            </div>
        `;

        await this.sendEmail(userId, subject, html);
    }

    // Send critical vulnerability alert
    async notifyCriticalFound(userId, scan, criticalVulns) {
        const settings = EmailService.getSettings(userId);
        if (!settings || !settings.notify_critical_found) return;
        if (!criticalVulns || criticalVulns.length === 0) return;

        const subject = `⚠️ KRITISCH: ${criticalVulns.length} kritische Schwachstellen in Scan #${scan.id}`;

        const vulnRows = criticalVulns.slice(0, 10).map(v => `
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #2a3548;">${v.ip_address}:${v.port}</td>
                <td style="padding: 8px; border-bottom: 1px solid #2a3548;">${v.cve_id || 'N/A'}</td>
                <td style="padding: 8px; border-bottom: 1px solid #2a3548; color: #ef4444;">${v.title}</td>
                <td style="padding: 8px; border-bottom: 1px solid #2a3548;">${v.cvss_score || 'N/A'}</td>
            </tr>
        `).join('');

        const html = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #ef4444, #dc2626); padding: 20px; border-radius: 8px 8px 0 0;">
                    <h1 style="color: white; margin: 0; font-size: 20px;">🚨 SecureScope - Kritische Schwachstellen</h1>
                </div>
                <div style="background: #1a2234; color: #e2e8f0; padding: 20px; border-radius: 0 0 8px 8px;">
                    <p style="color: #ef4444; font-weight: bold;">
                        ${criticalVulns.length} kritische Schwachstelle(n) in Scan #${scan.id} (${scan.target}) gefunden!
                    </p>
                    <table style="width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px;">
                        <thead>
                            <tr style="background: #0f1623;">
                                <th style="padding: 8px; text-align: left; color: #94a3b8;">Ziel</th>
                                <th style="padding: 8px; text-align: left; color: #94a3b8;">CVE</th>
                                <th style="padding: 8px; text-align: left; color: #94a3b8;">Schwachstelle</th>
                                <th style="padding: 8px; text-align: left; color: #94a3b8;">CVSS</th>
                            </tr>
                        </thead>
                        <tbody>${vulnRows}</tbody>
                    </table>
                    ${criticalVulns.length > 10 ? `<p style="color: #94a3b8;">... und ${criticalVulns.length - 10} weitere</p>` : ''}
                    <p style="color: #f59e0b; margin-top: 15px;">
                        ⚡ Sofortige Maßnahmen empfohlen. Bitte prüfen Sie die Ergebnisse im SecureScope Dashboard.
                    </p>
                    <p style="color: #64748b; font-size: 12px; margin-top: 20px;">
                        Diese E-Mail wurde automatisch von SecureScope generiert.
                    </p>
                </div>
            </div>
        `;

        await this.sendEmail(userId, subject, html);
    }
}

const emailServiceInstance = new EmailService();

module.exports = emailServiceInstance;