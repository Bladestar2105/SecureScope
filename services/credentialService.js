const { getDatabase } = require('../config/database');
const crypto = require('crypto');
const logger = require('./logger');

// Encryption key derived from environment or fallback
const ENCRYPTION_KEY = crypto.scryptSync(
    process.env.CREDENTIAL_SECRET || process.env.SESSION_SECRET || 'securescope-credential-key-change-me',
    'securescope-salt-v1', 32
);
const IV_LENGTH = 16;
const ALGORITHM = 'aes-256-gcm';

class CredentialService {

    // Encrypt sensitive data
    static _encrypt(text) {
        if (!text) return null;
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');
        return `${iv.toString('hex')}:${authTag}:${encrypted}`;
    }

    // Decrypt sensitive data
    static _decrypt(encryptedText) {
        if (!encryptedText) return null;
        try {
            const parts = encryptedText.split(':');
            if (parts.length !== 3) return null;
            const iv = Buffer.from(parts[0], 'hex');
            const authTag = Buffer.from(parts[1], 'hex');
            const encrypted = parts[2];
            const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
            decipher.setAuthTag(authTag);
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (err) {
            logger.error('Credential decryption failed:', err.message);
            return null;
        }
    }

    // Supported authentication methods
    static get AUTH_METHODS() {
        return {
            password: { label: 'Passwort', description: 'Benutzername/Passwort-Authentifizierung', icon: 'bi-key' },
            ssh_key: { label: 'SSH-Key', description: 'SSH Public/Private Key Authentifizierung', icon: 'bi-file-earmark-lock' },
            ssh_password: { label: 'SSH + Passwort', description: 'SSH mit Passwort-Authentifizierung', icon: 'bi-terminal' },
            active_directory: { label: 'Active Directory', description: 'Windows AD/LDAP Authentifizierung', icon: 'bi-windows' },
            snmp: { label: 'SNMP Community', description: 'SNMP Community String', icon: 'bi-hdd-network' },
            api_key: { label: 'API-Key', description: 'API-Schlüssel Authentifizierung', icon: 'bi-braces' },
            database: { label: 'Datenbank', description: 'Datenbank-Zugangsdaten', icon: 'bi-database' },
            certificate: { label: 'Zertifikat', description: 'Client-Zertifikat Authentifizierung', icon: 'bi-shield-lock' }
        };
    }

    // Get all credentials for a user (passwords masked)
    static getAll(userId, filters = {}) {
        const db = getDatabase();
        let query = 'SELECT id, name, credential_type, username, domain, auth_method, target_scope, description, tags, last_used_at, is_valid, created_at, updated_at FROM credentials WHERE created_by = ?';
        const params = [userId];

        if (filters.type) {
            query += ' AND credential_type = ?';
            params.push(filters.type);
        }
        if (filters.authMethod) {
            query += ' AND auth_method = ?';
            params.push(filters.authMethod);
        }
        if (filters.search) {
            query += ' AND (name LIKE ? OR username LIKE ? OR domain LIKE ? OR description LIKE ?)';
            const term = `%${filters.search}%`;
            params.push(term, term, term, term);
        }
        if (filters.valid !== undefined) {
            query += ' AND is_valid = ?';
            params.push(filters.valid ? 1 : 0);
        }

        query += ' ORDER BY name ASC';

        const results = db.prepare(query).all(...params);

        return results.map(cred => ({
            ...cred,
            tags: JSON.parse(cred.tags || '[]'),
            hasPassword: !!db.prepare('SELECT password_encrypted FROM credentials WHERE id = ?').get(cred.id)?.password_encrypted,
            hasSshKey: !!db.prepare('SELECT ssh_key_encrypted FROM credentials WHERE id = ?').get(cred.id)?.ssh_key_encrypted
        }));
    }

    // Get credential by ID (with decrypted data for internal use)
    static getById(id, userId, decrypt = false) {
        const db = getDatabase();
        const cred = db.prepare('SELECT * FROM credentials WHERE id = ? AND created_by = ?').get(id, userId);
        if (!cred) return null;

        const result = {
            ...cred,
            tags: JSON.parse(cred.tags || '[]')
        };

        if (decrypt) {
            result.password = this._decrypt(cred.password_encrypted);
            result.sshKey = this._decrypt(cred.ssh_key_encrypted);
        } else {
            result.hasPassword = !!cred.password_encrypted;
            result.hasSshKey = !!cred.ssh_key_encrypted;
            delete result.password_encrypted;
            delete result.ssh_key_encrypted;
        }

        return result;
    }

    // Create a new credential
    static create(userId, data) {
        const db = getDatabase();

        const authMethod = data.authMethod || data.auth_method || 'password';

        // Validate required fields
        if (!data.name) throw new Error('Name ist erforderlich');
        if (!authMethod) throw new Error('Authentifizierungsmethode ist erforderlich');

        const encryptedPassword = (data.password || data.ssh_key_password) ? this._encrypt(data.password || data.ssh_key_password) : null;
        const encryptedSshKey = (data.sshKey || data.ssh_key) ? this._encrypt(data.sshKey || data.ssh_key) : null;

        const result = db.prepare(`
            INSERT INTO credentials (name, credential_type, username, password_encrypted, ssh_key_encrypted,
                domain, auth_method, target_scope, description, tags, is_valid, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            data.name,
            data.credentialType || data.credential_type || 'password',
            data.username || null,
            encryptedPassword,
            encryptedSshKey,
            data.domain || null,
            authMethod,
            data.targetScope || data.target_scope || null,
            data.description || null,
            JSON.stringify(data.tags || []),
            1,
            userId
        );

        logger.info(`Credential created: ${data.name} (ID: ${result.lastInsertRowid}) by user ${userId}`);
        logger.audit('CREDENTIAL_CREATED', { credentialId: result.lastInsertRowid, name: data.name, authMethod: data.authMethod, userId });

        return result.lastInsertRowid;
    }

    // Update a credential
    static update(id, userId, data) {
        const db = getDatabase();

        // Verify ownership
        const existing = db.prepare('SELECT id FROM credentials WHERE id = ? AND created_by = ?').get(id, userId);
        if (!existing) throw new Error('Credential nicht gefunden oder keine Berechtigung');

        const updates = [];
        const params = [];

        if (data.name !== undefined) { updates.push('name = ?'); params.push(data.name); }
        if (data.username !== undefined) { updates.push('username = ?'); params.push(data.username); }
        if (data.domain !== undefined) { updates.push('domain = ?'); params.push(data.domain); }
        if (data.authMethod !== undefined || data.auth_method !== undefined) { updates.push('auth_method = ?'); params.push(data.authMethod || data.auth_method); }
        if (data.targetScope !== undefined || data.target_scope !== undefined) { updates.push('target_scope = ?'); params.push(data.targetScope || data.target_scope); }
        if (data.description !== undefined) { updates.push('description = ?'); params.push(data.description); }
        if (data.tags !== undefined) { updates.push('tags = ?'); params.push(JSON.stringify(data.tags)); }
        if (data.isValid !== undefined || data.is_valid !== undefined) { updates.push('is_valid = ?'); params.push((data.isValid || data.is_valid) ? 1 : 0); }
        if (data.credentialType !== undefined || data.credential_type !== undefined) { updates.push('credential_type = ?'); params.push(data.credentialType || data.credential_type); }

        // Re-encrypt password if provided
        if (data.password) {
            updates.push('password_encrypted = ?');
            params.push(this._encrypt(data.password));
        }
        if (data.sshKey || data.ssh_key) {
            updates.push('ssh_key_encrypted = ?');
            params.push(this._encrypt(data.sshKey || data.ssh_key));
        }

        if (updates.length === 0) return;

        updates.push('updated_at = CURRENT_TIMESTAMP');
        params.push(id, userId);

        db.prepare(`UPDATE credentials SET ${updates.join(', ')} WHERE id = ? AND created_by = ?`).run(...params);

        logger.info(`Credential updated: ID ${id} by user ${userId}`);
        logger.audit('CREDENTIAL_UPDATED', { credentialId: id, userId });
    }

    // Delete a credential
    static delete(id, userId) {
        const db = getDatabase();
        const result = db.prepare('DELETE FROM credentials WHERE id = ? AND created_by = ?').run(id, userId);
        if (result.changes === 0) throw new Error('Credential nicht gefunden oder keine Berechtigung');

        logger.info(`Credential deleted: ID ${id} by user ${userId}`);
        logger.audit('CREDENTIAL_DELETED', { credentialId: id, userId });
    }

    // Log credential usage
    static logUsage(credentialId, scanId, targetIp, targetPort, targetService, success, details, userId) {
        const db = getDatabase();
        db.prepare(`
            INSERT INTO credential_usage_log (credential_id, scan_id, target_ip, target_port, target_service, auth_success, details, used_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(credentialId, scanId || null, targetIp || null, targetPort || null, targetService || null, success ? 1 : 0, details || null, userId);

        // Update last_used_at
        db.prepare('UPDATE credentials SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(credentialId);
    }

    // Get usage log for a credential
    static getUsageLog(credentialId, userId) {
        const db = getDatabase();
        // Verify ownership
        const cred = db.prepare('SELECT id FROM credentials WHERE id = ? AND created_by = ?').get(credentialId, userId);
        if (!cred) return [];

        return db.prepare(`
            SELECT cul.*, s.target as scan_target
            FROM credential_usage_log cul
            LEFT JOIN scans s ON cul.scan_id = s.id
            WHERE cul.credential_id = ?
            ORDER BY cul.used_at DESC
            LIMIT 100
        `).all(credentialId);
    }

    // Get credentials applicable for a target
    static getForTarget(userId, targetIp, targetPort, targetService) {
        const db = getDatabase();
        return db.prepare(`
            SELECT id, name, credential_type, username, domain, auth_method, target_scope, description
            FROM credentials
            WHERE created_by = ? AND is_valid = 1
            AND (target_scope IS NULL OR target_scope = '' OR target_scope LIKE ? OR target_scope LIKE ? OR target_scope = '*')
            ORDER BY name ASC
        `).all(userId, `%${targetIp}%`, `%${targetService || ''}%`);
    }

    // Get credential statistics
    static getStats(userId) {
        const db = getDatabase();
        const total = db.prepare('SELECT COUNT(*) as count FROM credentials WHERE created_by = ?').get(userId);
        const byMethod = db.prepare('SELECT auth_method, COUNT(*) as count FROM credentials WHERE created_by = ? GROUP BY auth_method').all(userId);
        const valid = db.prepare('SELECT COUNT(*) as count FROM credentials WHERE created_by = ? AND is_valid = 1').get(userId);
        const recentUsage = db.prepare(`
            SELECT COUNT(*) as count FROM credential_usage_log cul
            JOIN credentials c ON cul.credential_id = c.id
            WHERE c.created_by = ? AND cul.used_at > datetime('now', '-30 days')
        `).get(userId);

        return {
            total: total.count,
            valid: valid.count,
            invalid: total.count - valid.count,
            byMethod,
            recentUsageCount: recentUsage.count
        };
    }
}

module.exports = CredentialService;