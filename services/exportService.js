const PDFDocument = require('pdfkit');
const { Parser } = require('json2csv');

class ExportService {
    /**
     * Export scan results as JSON
     * @param {Object} res Express response object
     * @param {Object} scan Scan metadata
     * @param {Array} results Scan results
     */
    exportJSON(res, scan, results) {
        const data = {
            scan: {
                id: scan.id,
                type: scan.scan_type,
                target: scan.target,
                status: scan.status,
                startedAt: scan.started_at,
                completedAt: scan.completed_at
            },
            summary: {
                totalPorts: results.length,
                critical: results.filter(r => r.risk_level === 'critical').length,
                warning: results.filter(r => r.risk_level === 'warning').length,
                safe: results.filter(r => r.risk_level === 'safe').length
            },
            results: results.map(r => ({
                ip: r.ip_address,
                port: r.port,
                protocol: r.protocol,
                service: r.service,
                product: r.service_product || null,
                version: r.service_version || null,
                banner: r.banner || null,
                cpe: r.service_cpe || null,
                os: r.os_name || null,
                state: r.state,
                riskLevel: r.risk_level
            }))
        };

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename=securescope_scan_${scan.id}.json`);
        res.json(data);
    }

    /**
     * Export scan results as CSV
     * @param {Object} res Express response object
     * @param {Object} scan Scan metadata
     * @param {Array} results Scan results
     */
    exportCSV(res, scan, results) {
        const fields = [
            { label: 'IP-Adresse', value: 'ip_address' },
            { label: 'Port', value: 'port' },
            { label: 'Protokoll', value: 'protocol' },
            { label: 'Service', value: 'service' },
            { label: 'Produkt', value: 'service_product' },
            { label: 'Version', value: 'service_version' },
            { label: 'Banner', value: 'banner' },
            { label: 'CPE', value: 'service_cpe' },
            { label: 'OS', value: 'os_name' },
            { label: 'Status', value: 'state' },
            { label: 'Risiko', value: 'risk_level' }
        ];

        const sanitize = (val) => {
            if (val === null || val === undefined) return '';
            const str = String(val);
            // Prevent formula injection (CSV Injection)
            if (/^[=@+\-]/.test(str)) {
                return "'" + str;
            }
            return str;
        };

        const sanitizedResults = results.map(r => ({
            ip_address: sanitize(r.ip_address),
            port: r.port,
            protocol: sanitize(r.protocol),
            service: sanitize(r.service),
            service_product: sanitize(r.service_product),
            service_version: sanitize(r.service_version),
            banner: sanitize(r.banner),
            service_cpe: sanitize(r.service_cpe),
            os_name: sanitize(r.os_name),
            state: sanitize(r.state),
            risk_level: sanitize(r.risk_level)
        }));

        const json2csvParser = new Parser({ fields });
        const csvData = json2csvParser.parse(sanitizedResults);

        const csv = [
            `# SecureScope Scan Report - ID: ${scan.id}`,
            `# Ziel: ${scan.target}`,
            `# Typ: ${scan.scan_type}`,
            `# Datum: ${scan.started_at}`,
            `# Status: ${scan.status}`,
            '',
            csvData
        ].join('\n');

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename=securescope_scan_${scan.id}.csv`);
        res.send(csv);
    }

    /**
     * Export scan results as PDF
     * @param {Object} res Express response object
     * @param {Object} scan Scan metadata
     * @param {Array} results Scan results
     */
    exportPDF(res, scan, results) {
        const doc = new PDFDocument({ margin: 50, size: 'A4' });

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=securescope_scan_${scan.id}.pdf`);

        doc.pipe(res);

        // Title
        doc.fontSize(24).font('Helvetica-Bold').text('SecureScope', { align: 'center' });
        doc.fontSize(14).font('Helvetica').text('Network Security Audit Report', { align: 'center' });
        doc.moveDown(2);

        // Scan Info
        doc.fontSize(16).font('Helvetica-Bold').text('Scan-Informationen');
        doc.moveDown(0.5);
        doc.fontSize(10).font('Helvetica');
        doc.text(`Scan-ID: ${scan.id}`);
        doc.text(`Ziel: ${scan.target}`);
        doc.text(`Scan-Typ: ${scan.scan_type}`);
        doc.text(`Status: ${scan.status}`);
        doc.text(`Gestartet: ${scan.started_at}`);
        doc.text(`Abgeschlossen: ${scan.completed_at || 'N/A'}`);
        doc.moveDown(1);

        // Summary
        const critical = results.filter(r => r.risk_level === 'critical').length;
        const warning = results.filter(r => r.risk_level === 'warning').length;
        const safe = results.filter(r => r.risk_level === 'safe').length;

        doc.fontSize(16).font('Helvetica-Bold').text('Zusammenfassung');
        doc.moveDown(0.5);
        doc.fontSize(10).font('Helvetica');
        doc.text(`Offene Ports gesamt: ${results.length}`);
        doc.fillColor('red').text(`Kritisch: ${critical}`);
        doc.fillColor('#cc8800').text(`Warnung: ${warning}`);
        doc.fillColor('green').text(`Sicher: ${safe}`);
        doc.fillColor('black');
        doc.moveDown(1);

        // Results Table
        if (results.length > 0) {
            doc.fontSize(16).font('Helvetica-Bold').text('Ergebnisse');
            doc.moveDown(0.5);

            // Table header
            const tableTop = doc.y;
            const colWidths = [80, 45, 80, 140, 60, 60];
            const headers = ['IP-Adresse', 'Port', 'Service', 'Produkt/Version', 'Status', 'Risiko'];

            doc.fontSize(9).font('Helvetica-Bold');
            let xPos = 50;
            headers.forEach((header, i) => {
                doc.text(header, xPos, tableTop, { width: colWidths[i] });
                xPos += colWidths[i];
            });

            doc.moveTo(50, tableTop + 15).lineTo(545, tableTop + 15).stroke();

            // Table rows
            doc.font('Helvetica').fontSize(8);
            let yPos = tableTop + 20;

            results.forEach((r, index) => {
                if (yPos > 750) {
                    doc.addPage();
                    yPos = 50;
                }

                xPos = 50;
                let productVersion = r.banner || r.service_product || '';
                if (productVersion.length > 30) productVersion = productVersion.substring(0, 30) + '...';
                const rowData = [r.ip_address, r.port.toString(), r.service || '', productVersion, r.state, r.risk_level];

                // Color based on risk
                if (r.risk_level === 'critical') doc.fillColor('red');
                else if (r.risk_level === 'warning') doc.fillColor('#cc8800');
                else if (r.risk_level === 'safe') doc.fillColor('green');
                else doc.fillColor('black');

                rowData.forEach((cell, i) => {
                    doc.text(cell, xPos, yPos, { width: colWidths[i] });
                    xPos += colWidths[i];
                });

                doc.fillColor('black');
                yPos += 15;
            });
        } else {
            doc.fontSize(12).text('Keine offenen Ports gefunden.', { align: 'center' });
        }

        // Footer
        doc.moveDown(2);
        doc.fontSize(8).fillColor('gray')
            .text(`Generiert von SecureScope am ${new Date().toLocaleString('de-DE')}`, { align: 'center' });

        doc.end();
    }
}

module.exports = new ExportService();
