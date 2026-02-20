const { WebSocketServer } = require('ws');
const logger = require('./logger');
const url = require('url');

class WebSocketService {
    constructor() {
        this.wss = null;
        this.handlers = new Map(); // path -> handler function
    }

    initialize(server) {
        if (this.wss) return;

        this.wss = new WebSocketServer({ noServer: true });

        server.on('upgrade', (request, socket, head) => {
            const { pathname } = url.parse(request.url);

            // Basic path matching (e.g., /shell/123)
            // We'll iterate through registered handlers to find a match
            let handled = false;

            for (const [route, handler] of this.handlers) {
                // Simple exact match or prefix match logic
                // If route is a regex, test it
                if (route instanceof RegExp) {
                    const match = route.exec(pathname);
                    if (match) {
                        this.wss.handleUpgrade(request, socket, head, (ws) => {
                            handler(ws, request, match);
                        });
                        handled = true;
                        break;
                    }
                } else if (pathname === route) {
                    this.wss.handleUpgrade(request, socket, head, (ws) => {
                        handler(ws, request);
                    });
                    handled = true;
                    break;
                }
            }

            if (!handled) {
                socket.destroy();
            }
        });

        logger.info('WebSocket Server initialized');
    }

    registerHandler(route, handler) {
        this.handlers.set(route, handler);
    }
}

module.exports = new WebSocketService();
