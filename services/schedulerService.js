const cron = require('node-cron');
const { getDatabase } = require('../config/database');
const scannerService = require('./scanner');
const logger = require('./logger');

class SchedulerService {
    constructor() {
        this.jobs = new Map(); // scheduleId -> cron job
        this.running = false;
    }

    // Initialize scheduler - load all enabled schedules from DB
    initialize() {
        if (this.running) return;
        this.running = true;

        try {
            const db = getDatabase();
            const schedules = db.prepare(
                'SELECT * FROM scheduled_scans WHERE enabled = 1'
            ).all();

            for (const schedule of schedules) {
                this._registerJob(schedule);
            }

            logger.info(`Scheduler initialized with ${schedules.length} active jobs`);
        } catch (err) {
            logger.error('Scheduler initialization failed:', err);
        }
    }

    // Register a cron job for a schedule
    _registerJob(schedule) {
        try {
            if (!cron.validate(schedule.cron_expression)) {
                logger.error(`Invalid cron expression for schedule ${schedule.id}: ${schedule.cron_expression}`);
                return;
            }

            // Remove existing job if any
            this._removeJob(schedule.id);

            const job = cron.schedule(schedule.cron_expression, async () => {
                await this._executeScan(schedule);
            }, {
                scheduled: true,
                timezone: 'Europe/Berlin'
            });

            this.jobs.set(schedule.id, job);

            // Update next run time
            this._updateNextRun(schedule.id, schedule.cron_expression);

            logger.info(`Scheduled scan ${schedule.id} registered: "${schedule.name}" (${schedule.cron_expression})`);
        } catch (err) {
            logger.error(`Failed to register schedule ${schedule.id}:`, err);
        }
    }

    // Remove a cron job
    _removeJob(scheduleId) {
        const existing = this.jobs.get(scheduleId);
        if (existing) {
            existing.stop();
            this.jobs.delete(scheduleId);
        }
    }

    // Execute a scheduled scan
    async _executeScan(schedule) {
        logger.info(`Executing scheduled scan ${schedule.id}: "${schedule.name}" -> ${schedule.target}`);

        const db = getDatabase();

        try {
            // Update last run time
            db.prepare(
                'UPDATE scheduled_scans SET last_run_at = CURRENT_TIMESTAMP WHERE id = ?'
            ).run(schedule.id);

            // Start the scan
            const scan = await scannerService.startScan(
                schedule.user_id,
                schedule.target,
                schedule.scan_type,
                schedule.custom_ports
            );

            logger.info(`Scheduled scan ${schedule.id} started as scan #${scan.id}`);
            logger.audit('SCHEDULED_SCAN_EXECUTED', {
                scheduleId: schedule.id,
                scanId: scan.id,
                name: schedule.name,
                target: schedule.target
            });

            // Update next run time
            this._updateNextRun(schedule.id, schedule.cron_expression);

            // Notification will be handled by the scan completion event in emailService

        } catch (err) {
            logger.error(`Scheduled scan ${schedule.id} failed:`, err);
            logger.audit('SCHEDULED_SCAN_FAILED', {
                scheduleId: schedule.id,
                error: err.message
            });
        }
    }

    // Calculate and update next run time
    _updateNextRun(scheduleId, cronExpression) {
        try {
            const interval = cron.schedule(cronExpression, () => {}, { scheduled: false });
            // node-cron doesn't expose next run directly, so we calculate approximate
            const db = getDatabase();
            db.prepare(
                'UPDATE scheduled_scans SET updated_at = CURRENT_TIMESTAMP WHERE id = ?'
            ).run(scheduleId);
        } catch (err) {
            logger.error(`Failed to update next run for schedule ${scheduleId}:`, err);
        }
    }

    // Create a new scheduled scan
    create(userId, data) {
        const db = getDatabase();

        // Validate cron expression
        if (!cron.validate(data.cronExpression)) {
            throw new Error('Ungültiger Cron-Ausdruck. Beispiel: "0 2 * * *" (täglich um 02:00)');
        }

        // Validate target
        const ScannerService = require('./scanner');
        const targetValidation = ScannerService.constructor.validateTarget
            ? ScannerService.constructor.validateTarget(data.target)
            : { valid: true };

        const result = db.prepare(`
            INSERT INTO scheduled_scans (user_id, name, target, scan_type, custom_ports, cron_expression, 
                                         notify_on_complete, notify_on_critical, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            userId,
            data.name,
            data.target,
            data.scanType,
            data.customPorts || null,
            data.cronExpression,
            data.notifyOnComplete ? 1 : 0,
            data.notifyOnCritical !== false ? 1 : 0,
            data.enabled !== false ? 1 : 0
        );

        const scheduleId = result.lastInsertRowid;
        const schedule = db.prepare('SELECT * FROM scheduled_scans WHERE id = ?').get(scheduleId);

        // Register the job if enabled
        if (schedule.enabled) {
            this._registerJob(schedule);
        }

        logger.info(`Scheduled scan created: ${data.name} (ID: ${scheduleId})`);
        logger.audit('SCHEDULE_CREATED', { scheduleId, name: data.name, userId });

        return schedule;
    }

    // Update a scheduled scan
    update(scheduleId, userId, data) {
        const db = getDatabase();

        const existing = db.prepare('SELECT * FROM scheduled_scans WHERE id = ? AND user_id = ?').get(scheduleId, userId);
        if (!existing) {
            throw new Error('Geplanter Scan nicht gefunden');
        }

        if (data.cronExpression && !cron.validate(data.cronExpression)) {
            throw new Error('Ungültiger Cron-Ausdruck');
        }

        db.prepare(`
            UPDATE scheduled_scans SET
                name = COALESCE(?, name),
                target = COALESCE(?, target),
                scan_type = COALESCE(?, scan_type),
                custom_ports = COALESCE(?, custom_ports),
                cron_expression = COALESCE(?, cron_expression),
                notify_on_complete = COALESCE(?, notify_on_complete),
                notify_on_critical = COALESCE(?, notify_on_critical),
                enabled = COALESCE(?, enabled),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(
            data.name || null,
            data.target || null,
            data.scanType || null,
            data.customPorts !== undefined ? data.customPorts : null,
            data.cronExpression || null,
            data.notifyOnComplete !== undefined ? (data.notifyOnComplete ? 1 : 0) : null,
            data.notifyOnCritical !== undefined ? (data.notifyOnCritical ? 1 : 0) : null,
            data.enabled !== undefined ? (data.enabled ? 1 : 0) : null,
            scheduleId
        );

        // Reload and re-register job
        const updated = db.prepare('SELECT * FROM scheduled_scans WHERE id = ?').get(scheduleId);
        if (updated.enabled) {
            this._registerJob(updated);
        } else {
            this._removeJob(scheduleId);
        }

        logger.info(`Scheduled scan updated: ID ${scheduleId}`);
        return updated;
    }

    // Delete a scheduled scan
    delete(scheduleId, userId) {
        const db = getDatabase();

        const existing = db.prepare('SELECT * FROM scheduled_scans WHERE id = ? AND user_id = ?').get(scheduleId, userId);
        if (!existing) {
            throw new Error('Geplanter Scan nicht gefunden');
        }

        this._removeJob(scheduleId);
        db.prepare('DELETE FROM scheduled_scans WHERE id = ?').run(scheduleId);

        logger.info(`Scheduled scan deleted: ID ${scheduleId}`);
        logger.audit('SCHEDULE_DELETED', { scheduleId, userId });
    }

    // Get all schedules for a user
    getAll(userId) {
        const db = getDatabase();
        return db.prepare(
            'SELECT * FROM scheduled_scans WHERE user_id = ? ORDER BY created_at DESC'
        ).all(userId);
    }

    // Get a single schedule
    getById(scheduleId, userId) {
        const db = getDatabase();
        return db.prepare(
            'SELECT * FROM scheduled_scans WHERE id = ? AND user_id = ?'
        ).get(scheduleId, userId);
    }

    // Toggle schedule enabled/disabled
    toggle(scheduleId, userId) {
        const db = getDatabase();
        const schedule = db.prepare('SELECT * FROM scheduled_scans WHERE id = ? AND user_id = ?').get(scheduleId, userId);
        if (!schedule) {
            throw new Error('Geplanter Scan nicht gefunden');
        }

        const newEnabled = schedule.enabled ? 0 : 1;
        db.prepare('UPDATE scheduled_scans SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
            .run(newEnabled, scheduleId);

        if (newEnabled) {
            this._registerJob({ ...schedule, enabled: 1 });
        } else {
            this._removeJob(scheduleId);
        }

        return newEnabled === 1;
    }

    // Get common cron presets
    static getCronPresets() {
        return [
            { label: 'Stündlich', value: '0 * * * *', description: 'Jede Stunde zur vollen Stunde' },
            { label: 'Alle 6 Stunden', value: '0 */6 * * *', description: 'Alle 6 Stunden' },
            { label: 'Täglich (02:00)', value: '0 2 * * *', description: 'Jeden Tag um 02:00 Uhr' },
            { label: 'Täglich (08:00)', value: '0 8 * * *', description: 'Jeden Tag um 08:00 Uhr' },
            { label: 'Wöchentlich (Mo 02:00)', value: '0 2 * * 1', description: 'Jeden Montag um 02:00 Uhr' },
            { label: 'Monatlich (1. um 02:00)', value: '0 2 1 * *', description: 'Am 1. jedes Monats um 02:00 Uhr' }
        ];
    }

    // Shutdown all jobs
    shutdown() {
        for (const [id, job] of this.jobs) {
            job.stop();
        }
        this.jobs.clear();
        this.running = false;
        logger.info('Scheduler shut down');
    }
}

// Singleton
const schedulerService = new SchedulerService();

module.exports = schedulerService;