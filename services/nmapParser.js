class NmapParser {
    // Known critical ports and their risk levels
    static get CRITICAL_PORTS() {
        return {
            21: { service: 'FTP', risk: 'critical', description: 'File Transfer Protocol - oft unverschlüsselt' },
            22: { service: 'SSH', risk: 'safe', description: 'Secure Shell' },
            23: { service: 'Telnet', risk: 'critical', description: 'Telnet - unverschlüsselte Verbindung' },
            25: { service: 'SMTP', risk: 'warning', description: 'Simple Mail Transfer Protocol' },
            53: { service: 'DNS', risk: 'safe', description: 'Domain Name System' },
            80: { service: 'HTTP', risk: 'warning', description: 'Unverschlüsselter Webserver' },
            110: { service: 'POP3', risk: 'warning', description: 'Post Office Protocol - oft unverschlüsselt' },
            111: { service: 'RPCBind', risk: 'critical', description: 'RPC Portmapper - Sicherheitsrisiko' },
            135: { service: 'MSRPC', risk: 'critical', description: 'Microsoft RPC - häufiges Angriffsziel' },
            139: { service: 'NetBIOS', risk: 'critical', description: 'NetBIOS Session Service' },
            143: { service: 'IMAP', risk: 'warning', description: 'Internet Message Access Protocol' },
            443: { service: 'HTTPS', risk: 'safe', description: 'Verschlüsselter Webserver' },
            445: { service: 'SMB', risk: 'critical', description: 'Server Message Block - häufiges Angriffsziel' },
            993: { service: 'IMAPS', risk: 'safe', description: 'IMAP über SSL' },
            995: { service: 'POP3S', risk: 'safe', description: 'POP3 über SSL' },
            1433: { service: 'MSSQL', risk: 'critical', description: 'Microsoft SQL Server' },
            1521: { service: 'Oracle', risk: 'critical', description: 'Oracle Database' },
            3306: { service: 'MySQL', risk: 'critical', description: 'MySQL Database' },
            3389: { service: 'RDP', risk: 'critical', description: 'Remote Desktop Protocol' },
            5432: { service: 'PostgreSQL', risk: 'critical', description: 'PostgreSQL Database' },
            5900: { service: 'VNC', risk: 'critical', description: 'Virtual Network Computing' },
            6379: { service: 'Redis', risk: 'critical', description: 'Redis Database' },
            8080: { service: 'HTTP-Alt', risk: 'warning', description: 'Alternativer HTTP Port' },
            8443: { service: 'HTTPS-Alt', risk: 'warning', description: 'Alternativer HTTPS Port' },
            27017: { service: 'MongoDB', risk: 'critical', description: 'MongoDB Database' }
        };
    }

    // Get risk level for a port based on service info
    static getRiskLevel(port, state, serviceName) {
        if (state !== 'open') return 'info';
        const portInfo = NmapParser.CRITICAL_PORTS[port];
        if (portInfo) return portInfo.risk;

        // Additional risk assessment based on service name
        const svcLower = (serviceName || '').toLowerCase();
        if (['telnet', 'ftp', 'rlogin', 'rsh'].includes(svcLower)) return 'critical';
        if (['http', 'smtp', 'pop3', 'imap'].includes(svcLower)) return 'warning';
        if (['https', 'ssh', 'imaps', 'pop3s', 'smtps'].includes(svcLower)) return 'safe';

        return 'warning';
    }

    // Get service name for a port (fallback if nmap doesn't detect)
    static getServiceName(port) {
        const portInfo = NmapParser.CRITICAL_PORTS[port];
        return portInfo ? portInfo.service : 'unknown';
    }

    /**
     * Parse Nmap XML output into structured results
     */
    static parseXML(xmlData) {
        const results = [];

        // Parse each host block
        const hostRegex = /<host\b[^>]*>([\s\S]*?)<\/host>/g;
        let hostMatch;

        while ((hostMatch = hostRegex.exec(xmlData)) !== null) {
            const hostBlock = hostMatch[1];

            // Extract IP address
            const addrMatch = hostBlock.match(/<address\s+addr="([^"]+)"\s+addrtype="ipv4"/);
            if (!addrMatch) continue;
            const ip = addrMatch[1];

            // Check host status
            const statusMatch = hostBlock.match(/<status\s+state="([^"]+)"/);
            if (statusMatch && statusMatch[1] !== 'up') continue;

            // Extract OS detection info
            let osName = null;
            let osAccuracy = 0;
            const osMatchRegex = /<osmatch\s+name="([^"]+)"[^>]*accuracy="(\d+)"/g;
            let osMatch;
            while ((osMatch = osMatchRegex.exec(hostBlock)) !== null) {
                const acc = parseInt(osMatch[2]);
                if (acc > osAccuracy) {
                    osName = osMatch[1];
                    osAccuracy = acc;
                }
            }

            // Extract ports
            const portRegex = /<port\s+protocol="([^"]+)"\s+portid="(\d+)">([\s\S]*?)<\/port>/g;
            let portMatch;

            while ((portMatch = portRegex.exec(hostBlock)) !== null) {
                const protocol = portMatch[1];
                const port = parseInt(portMatch[2]);
                const portBlock = portMatch[3];

                // Get port state
                const stateMatch = portBlock.match(/<state\s+state="([^"]+)"/);
                if (!stateMatch) continue;
                const state = stateMatch[1];

                if (state !== 'open') continue;

                // Extract service info from Nmap's service detection
                let serviceName = '';
                let serviceProduct = '';
                let serviceVersion = '';
                let serviceExtraInfo = '';
                let serviceCPE = '';
                let tunnel = '';

                const serviceMatch = portBlock.match(/<service\s+([^>]*?)\/?>(?:<\/service>)?/);
                if (serviceMatch) {
                    const attrs = serviceMatch[1];

                    const nameM = attrs.match(/name="([^"]+)"/);
                    if (nameM) serviceName = nameM[1];

                    const productM = attrs.match(/product="([^"]+)"/);
                    if (productM) serviceProduct = productM[1];

                    const versionM = attrs.match(/version="([^"]+)"/);
                    if (versionM) serviceVersion = versionM[1];

                    const extraM = attrs.match(/extrainfo="([^"]+)"/);
                    if (extraM) serviceExtraInfo = extraM[1];

                    const tunnelM = attrs.match(/tunnel="([^"]+)"/);
                    if (tunnelM) tunnel = tunnelM[1];
                }

                // Extract CPE(s)
                const cpeMatches = portBlock.match(/<cpe>([^<]+)<\/cpe>/g);
                if (cpeMatches && cpeMatches.length > 0) {
                    serviceCPE = cpeMatches.map(c => c.replace(/<\/?cpe>/g, '')).join(',');
                }

                // Build display service name
                let displayService = serviceName || NmapParser.getServiceName(port);
                if (tunnel === 'ssl') displayService = `${displayService}/ssl`;

                // Build banner string (human-readable summary)
                let banner = '';
                if (serviceProduct) {
                    banner = serviceProduct;
                    if (serviceVersion) banner += '/' + serviceVersion;
                    if (serviceExtraInfo) banner += ' ' + serviceExtraInfo;
                }

                const riskLevel = NmapParser.getRiskLevel(port, state, serviceName);

                results.push({
                    ip,
                    port,
                    protocol,
                    state,
                    service: displayService,
                    service_product: serviceProduct || null,
                    service_version: serviceVersion || null,
                    service_extra: serviceExtraInfo || null,
                    service_cpe: serviceCPE || null,
                    banner: banner || null,
                    os_name: osName,
                    os_accuracy: osAccuracy,
                    riskLevel
                });
            }
        }

        return results;
    }
}

module.exports = NmapParser;
