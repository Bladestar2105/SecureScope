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
        // Format log entry
        const logEntry = {
            timestamp: info.timestamp || new Date().toISOString(),
            level: info.level,
            message: info.message,
            meta: info.metadata || {}
        };

        // Add to buffer
        this.buffer.push(logEntry);
        if (this.buffer.length > this.MAX_BUFFER) {
            this.buffer.shift();
        }

        // Send to all connected clients
        const data = `data: ${JSON.stringify(logEntry)}\n\n`;
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
            client.write(`data: ${JSON.stringify(logEntry)}\n\n`);
        } catch (e) {
            this.removeClient(client);
        }
    }
}

// Singleton
module.exports = new LogStreamService();
