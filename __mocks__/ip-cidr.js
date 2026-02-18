console.log("Using Mock IPCIDR");

class IPCIDR {
    constructor(cidr) {
        this.cidr = cidr;
    }

    isValid() {
        // Simple mock validation (legacy support if needed, but we switched to static)
        return this.cidr && (this.cidr.includes('/') || this.cidr.match(/^\d+\.\d+\.\d+\.\d+$/));
    }

    static isValidCIDR(cidr) {
        return cidr && cidr.includes('/');
    }

    toArray() {
        return [];
    }
}

module.exports = IPCIDR;
