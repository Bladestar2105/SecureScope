const EventEmitter = require('events');

class LogStreamService extends EventEmitter {
    constructor() {
        super();
        this.clients = new Set();
        this.buffer = []; // Keep a small buffer of recent logs for new connections
        this.MAX_BUFFER = 100;
    }

    addClient(res) {
        this.clients.add(res);
        // Send buffer immediately
        for (const log of this.buffer) {
            this.sendToClient(res, log);
        }
    }

    removeClient(res) {
        this.clients.delete(res);
    }

    broadcast(info) {
        if (!info) return;

        // Extract standard fields and metadata
        // Winston 3.x puts metadata at top level, but some transports/formats might nest it
        const { timestamp, level, message, stack, metadata, ...meta } = info;

        // Combine remaining properties and explicit metadata
        const finalMeta = { ...meta, ...(metadata || {}) };

        // Format log entry
        const logEntry = {
            timestamp: timestamp || new Date().toISOString(),
            level: level || 'info',
            message: message || '',
            meta: finalMeta
        };

        // Add to buffer
        this.buffer.push(logEntry);
        if (this.buffer.length > this.MAX_BUFFER) {
            this.buffer.shift();
        }

        // Send to all connected clients
        // IMPORTANT: SSE requires real newlines (\n), not escaped literals
        const data = "data: " + JSON.stringify(logEntry) + "\n\n";
        for (const client of this.clients) {
            try {
                client.write(data);
            } catch (e) {
                this.removeClient(client);
            }
        }
    }

    sendToClient(client, logEntry) {
        try {
            // IMPORTANT: SSE requires real newlines (\n), not escaped literals
            client.write("data: " + JSON.stringify(logEntry) + "\n\n");
        } catch (e) {
            this.removeClient(client);
        }
    }
}

// Singleton
module.exports = new LogStreamService();
