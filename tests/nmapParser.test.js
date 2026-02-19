const NmapParser = require('../services/nmapParser');

describe('NmapParser', () => {
    describe('getRiskLevel', () => {
        test('should return info for non-open ports', () => {
            expect(NmapParser.getRiskLevel(80, 'closed')).toBe('info');
            expect(NmapParser.getRiskLevel(443, 'filtered')).toBe('info');
            expect(NmapParser.getRiskLevel(22, 'unfiltered')).toBe('info');
        });

        test('should return risk based on known critical ports', () => {
            expect(NmapParser.getRiskLevel(21, 'open')).toBe('critical'); // FTP
            expect(NmapParser.getRiskLevel(22, 'open')).toBe('safe');     // SSH
            expect(NmapParser.getRiskLevel(23, 'open')).toBe('critical'); // Telnet
            expect(NmapParser.getRiskLevel(80, 'open')).toBe('warning');  // HTTP
            expect(NmapParser.getRiskLevel(443, 'open')).toBe('safe');    // HTTPS
            expect(NmapParser.getRiskLevel(445, 'open')).toBe('critical'); // SMB
            expect(NmapParser.getRiskLevel(3306, 'open')).toBe('critical'); // MySQL
            expect(NmapParser.getRiskLevel(3389, 'open')).toBe('critical'); // RDP
        });

        test('should return risk based on service name for unknown ports', () => {
            // Critical services
            expect(NmapParser.getRiskLevel(9999, 'open', 'telnet')).toBe('critical');
            expect(NmapParser.getRiskLevel(9999, 'open', 'ftp')).toBe('critical');
            expect(NmapParser.getRiskLevel(9999, 'open', 'mysql')).toBe('critical');
            expect(NmapParser.getRiskLevel(9999, 'open', 'postgresql')).toBe('critical');
            expect(NmapParser.getRiskLevel(9999, 'open', 'rdp')).toBe('critical');

            // Warning services
            expect(NmapParser.getRiskLevel(9999, 'open', 'http')).toBe('warning');
            expect(NmapParser.getRiskLevel(9999, 'open', 'smtp')).toBe('warning');
            expect(NmapParser.getRiskLevel(9999, 'open', 'sip')).toBe('warning');

            // Safe services
            expect(NmapParser.getRiskLevel(9999, 'open', 'https')).toBe('safe');
            expect(NmapParser.getRiskLevel(9999, 'open', 'ssh')).toBe('safe');
            expect(NmapParser.getRiskLevel(9999, 'open', 'dns')).toBe('safe');
            expect(NmapParser.getRiskLevel(9999, 'open', 'ntp')).toBe('safe');
        });

        test('should be case-insensitive for service names', () => {
            expect(NmapParser.getRiskLevel(9999, 'open', 'HTTP')).toBe('warning');
            expect(NmapParser.getRiskLevel(9999, 'open', 'Ftp')).toBe('critical');
            expect(NmapParser.getRiskLevel(9999, 'open', 'sSh')).toBe('safe');
        });

        test('should return warning for unknown services on unknown ports', () => {
            expect(NmapParser.getRiskLevel(9999, 'open', 'unknown-service')).toBe('warning');
            expect(NmapParser.getRiskLevel(9999, 'open', null)).toBe('warning');
            expect(NmapParser.getRiskLevel(9999, 'open', undefined)).toBe('warning');
        });
    });

    describe('getServiceName', () => {
        test('should return known service name for critical ports', () => {
            expect(NmapParser.getServiceName(21)).toBe('FTP');
            expect(NmapParser.getServiceName(22)).toBe('SSH');
            expect(NmapParser.getServiceName(80)).toBe('HTTP');
        });

        test('should return unknown for unknown ports', () => {
            expect(NmapParser.getServiceName(9999)).toBe('unknown');
        });
    });

    describe('parseXML', () => {
        test('should correctly parse nmap XML output', () => {
            const xmlData = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O 127.0.0.1" start="1625050000" version="7.91" xmloutputversion="1.05">
<host startstr="Wed Jun 30 10:06:40 2021" endstr="Wed Jun 30 10:06:55 2021"><status state="up" reason="localhost-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu 4ubuntu0.2" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:8.2p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.41</cpe></service></port>
</ports>
<os><osmatch name="Linux 5.4" accuracy="100" line="63544"/></os>
</host>
</nmaprun>`;

            const results = NmapParser.parseXML(xmlData);

            expect(results).toHaveLength(2);

            // Check SSH port
            const ssh = results.find(r => r.port === 22);
            expect(ssh.ip).toBe('127.0.0.1');
            expect(ssh.service).toBe('ssh');
            expect(ssh.service_product).toBe('OpenSSH');
            expect(ssh.service_version).toBe('8.2p1');
            expect(ssh.riskLevel).toBe('safe');
            expect(ssh.os_name).toBe('Linux 5.4');

            // Check HTTP port
            const http = results.find(r => r.port === 80);
            expect(http.ip).toBe('127.0.0.1');
            expect(http.service).toBe('http');
            expect(http.banner).toContain('Apache httpd/2.4.41');
            expect(http.riskLevel).toBe('warning');
        });

        test('should handle host with no open ports', () => {
            const xmlData = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports></ports></host>
</nmaprun>`;
            const results = NmapParser.parseXML(xmlData);
            expect(results).toHaveLength(0);
        });

        test('should ignore down hosts', () => {
            const xmlData = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host><status state="down"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port portid="80"><state state="open"/></port></ports></host>
</nmaprun>`;
            const results = NmapParser.parseXML(xmlData);
            expect(results).toHaveLength(0);
        });
    });
});
