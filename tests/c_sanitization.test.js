const assert = require('assert');

function sanitizeCCode(code) {
    const lines = code.split(/\r?\n/);
    const outputLines = [];
    let buffer = '';
    let inMultiline = false;

    for (let line of lines) {
        if (inMultiline) {
            buffer += line.trimStart();
        } else {
            buffer = line;
        }

        // Check quote parity of buffer
        let quotes = 0;
        for (let i = 0; i < buffer.length; i++) {
            if (buffer[i] === '"') {
                // Check escapes: count preceding backslashes
                let backslashes = 0;
                let j = i - 1;
                while (j >= 0 && buffer[j] === '\\') {
                    backslashes++;
                    j--;
                }
                if (backslashes % 2 === 0) {
                    quotes++;
                }
            }
        }

        if (quotes % 2 !== 0) {
            inMultiline = true;
        } else {
            outputLines.push(buffer);
            inMultiline = false;
            buffer = '';
        }
    }
    if (inMultiline) outputLines.push(buffer);

    return outputLines.join('\n');
}

// Test cases
const test1 = `char c[] = "\\x01\\x02
\\x03\\x04";`;
const expected1 = `char c[] = "\\x01\\x02\\x03\\x04";`;

const test2 = `printf("Hello
World");`;
const expected2 = `printf("HelloWorld");`;

const test3 = `char valid[] = "\\x01";
char invalid[] = "\\x02
    \\x03";`; // Indented
const expected_contains = `char invalid[] = "\\x02\\x03";`; // Spaces removed

// Run tests
try {
    const res1 = sanitizeCCode(test1);
    console.log('Test 1:', res1 === expected1 ? 'PASS' : `FAIL\nExpected:\n${expected1}\nGot:\n${res1}`);

    const res2 = sanitizeCCode(test2);
    console.log('Test 2:', res2 === expected2 ? 'PASS' : `FAIL\nExpected:\n${expected2}\nGot:\n${res2}`);

    const res3 = sanitizeCCode(test3);
    console.log('Test 3:', res3.includes(expected_contains) ? 'PASS' : `FAIL\nGot:\n${res3}`);

} catch (e) {
    console.error(e);
}
