console.log("Using Mock IPCIDR");

class IPCIDR {
    constructor(cidr) {
        this.cidr = cidr;
    }

    isValid() {
        // Simple mock validation
        return this.cidr && (this.cidr.includes('/') || this.cidr.match(/^\d+\.\d+\.\d+\.\d+$/));
    }

    toArray() {
        return [];
    }
}

module.exports = IPCIDR;
