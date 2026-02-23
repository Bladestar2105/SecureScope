jest.mock('../config/database', () => ({
    getDatabase: jest.fn()
}), { virtual: true });

jest.mock('../services/logger', () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    audit: jest.fn()
}), { virtual: true });

const CVESyncService = require('../services/cveSyncService');

describe('CVESyncService.parseCVEv5', () => {
    test('should return null if cveId is missing', () => {
        const data = {
            cveMetadata: {
                state: 'PUBLISHED'
            }
        };
        expect(CVESyncService.parseCVEv5(data)).toBeNull();

        const dataNoMeta = {
            containers: {}
        };
        expect(CVESyncService.parseCVEv5(dataNoMeta)).toBeNull();
    });

    test('should extract basic metadata correctly', () => {
        const data = {
            cveMetadata: {
                cveId: 'CVE-2023-1234',
                state: 'PUBLISHED',
                datePublished: '2023-01-01T00:00:00Z',
                dateUpdated: '2023-01-02T00:00:00Z'
            }
        };
        const result = CVESyncService.parseCVEv5(data);
        expect(result.cveId).toBe('CVE-2023-1234');
        expect(result.state).toBe('PUBLISHED');
        expect(result.datePublished).toBe('2023-01-01T00:00:00Z');
        expect(result.dateUpdated).toBe('2023-01-02T00:00:00Z');
    });

    test('should use default state if missing', () => {
        const data = {
            cveMetadata: {
                cveId: 'CVE-2023-1234'
            }
        };
        const result = CVESyncService.parseCVEv5(data);
        expect(result.state).toBe('PUBLISHED');
    });

    describe('title generation', () => {
        test('should prioritize cna.title', () => {
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {
                        title: 'Explicit Title',
                        descriptions: [{ lang: 'en', value: 'Fallback description' }]
                    }
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.title).toBe('Explicit Title');
        });

        test('should fallback to description if title is missing', () => {
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {
                        descriptions: [{ lang: 'en', value: 'Fallback description' }]
                    }
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.title).toBe('Fallback description');
        });

        test('should truncate description fallback for title to 200 chars', () => {
            const longDesc = 'A'.repeat(300);
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {
                        descriptions: [{ lang: 'en', value: longDesc }]
                    }
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.title.length).toBe(200);
        });

        test('should fallback to cveId if title and description are missing', () => {
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {}
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.title).toBe('CVE-2023-1234');
        });
    });

    describe('description selection', () => {
        test('should prioritize English description', () => {
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {
                        descriptions: [
                            { lang: 'de', value: 'German description' },
                            { lang: 'en', value: 'English description' },
                            { lang: 'fr', value: 'French description' }
                        ]
                    }
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.description).toBe('English description');
        });

        test('should fallback to first available description if English is missing', () => {
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {
                        descriptions: [
                            { lang: 'de', value: 'German description' },
                            { lang: 'fr', value: 'French description' }
                        ]
                    }
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.description).toBe('German description');
        });

        test('should handle lang starting with en (e.g., en-US)', () => {
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {
                        descriptions: [
                            { lang: 'en-US', value: 'US English description' }
                        ]
                    }
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.description).toBe('US English description');
        });
    });

    describe('CVSS extraction and severity derivation', () => {
        test('should prioritize CVSS versions: 3.1 > 3.0 > 4.0 > 2.0 within a metric object', () => {
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {
                        metrics: [
                            {
                                cvssV2_0: { baseScore: 2.0, vectorString: 'V2', baseSeverity: 'LOW' },
                                cvssV4_0: { baseScore: 4.0, vectorString: 'V4', baseSeverity: 'MEDIUM' },
                                cvssV3_0: { baseScore: 3.0, vectorString: 'V3', baseSeverity: 'MEDIUM' },
                                cvssV3_1: { baseScore: 3.1, vectorString: 'V3.1', baseSeverity: 'MEDIUM' }
                            }
                        ]
                    }
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.cvssScore).toBe(3.1);
            expect(result.cvssVector).toBe('V3.1');
        });

        test('should use the first metric object that contains a supported CVSS version', () => {
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {
                        metrics: [
                            { cvssV2_0: { baseScore: 2.0, vectorString: 'V2', baseSeverity: 'LOW' } },
                            { cvssV3_1: { baseScore: 3.1, vectorString: 'V3.1', baseSeverity: 'MEDIUM' } }
                        ]
                    }
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            // It picks the first one and breaks
            expect(result.cvssScore).toBe(2.0);
        });

        test('should derive severity from score if baseSeverity is missing', () => {
            const testCases = [
                { score: 9.5, expected: 'critical' },
                { score: 8.5, expected: 'high' },
                { score: 5.5, expected: 'medium' },
                { score: 2.5, expected: 'low' }
            ];

            testCases.forEach(({ score, expected }) => {
                const data = {
                    cveMetadata: { cveId: 'CVE-2023-1234' },
                    containers: {
                        cna: {
                            metrics: [{ cvssV3_1: { baseScore: score } }]
                        }
                    }
                };
                const result = CVESyncService.parseCVEv5(data);
                expect(result.severity).toBe(expected);
            });
        });

        test('should use explicit baseSeverity (lowercase) if provided', () => {
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {
                        metrics: [{ cvssV3_1: { baseScore: 9.0, baseSeverity: 'HIGH' } }]
                    }
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.severity).toBe('high');
        });
    });

    describe('affected products and references', () => {
        test('should extract and format affected products correctly', () => {
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {
                        affected: [
                            { vendor: 'Microsoft', product: 'Windows' },
                            { vendor: 'Linux', product: 'Kernel' },
                            { product: 'UnknownVendorProduct' }
                        ]
                    }
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.affectedProducts).toBe('Microsoft/Windows, Linux/Kernel, unknown/UnknownVendorProduct');
        });

        test('should limit affected products to 20', () => {
            const affected = [];
            for (let i = 0; i < 25; i++) {
                affected.push({ vendor: 'V', product: 'P' + i });
            }
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: { cna: { affected } }
            };
            const result = CVESyncService.parseCVEv5(data);
            const products = result.affectedProducts.split(', ');
            expect(products.length).toBe(20);
        });

        test('should extract references correctly', () => {
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: {
                    cna: {
                        references: [
                            { url: 'https://example.com/1', name: 'Ref 1', tags: ['vendor-advisory'] },
                            { url: 'https://example.com/2' }
                        ]
                    }
                }
            };
            const result = CVESyncService.parseCVEv5(data);
            const refs = JSON.parse(result.referencesJson);
            expect(refs.length).toBe(2);
            expect(refs[0]).toEqual({ url: 'https://example.com/1', name: 'Ref 1', tags: ['vendor-advisory'] });
            expect(refs[1]).toEqual({ url: 'https://example.com/2', name: null, tags: [] });
        });

        test('should limit references to 10', () => {
            const references = [];
            for (let i = 0; i < 15; i++) {
                references.push({ url: 'https://example.com/' + i });
            }
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: { cna: { references } }
            };
            const result = CVESyncService.parseCVEv5(data);
            const refs = JSON.parse(result.referencesJson);
            expect(refs.length).toBe(10);
        });
    });

    describe('final field truncation', () => {
        test('should truncate title to 500 characters', () => {
            const longTitle = 'A'.repeat(600);
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: { cna: { title: longTitle } }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.title.length).toBe(500);
        });

        test('should truncate description to 5000 characters', () => {
            const longDesc = 'A'.repeat(6000);
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: { cna: { descriptions: [{ lang: 'en', value: longDesc }] } }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.description.length).toBe(5000);
        });

        test('should truncate affectedProducts to 2000 characters', () => {
            const affected = [];
            // Create 20 long product strings
            for (let i = 0; i < 20; i++) {
                affected.push({ vendor: 'V'.repeat(100), product: 'P'.repeat(100) + i });
            }
            const data = {
                cveMetadata: { cveId: 'CVE-2023-1234' },
                containers: { cna: { affected } }
            };
            const result = CVESyncService.parseCVEv5(data);
            expect(result.affectedProducts.length).toBe(2000);
        });
    });
});
