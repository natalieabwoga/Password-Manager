"use strict";

const expect = require('expect.js');
const { Keychain } = require('../password-manager');
const { stringToBuffer, encodeBuffer } = require('../lib');
const { subtle } = require('crypto').webcrypto;

function expectReject(promise) {
    return promise.then(
        (result) => expect().fail(`Expected failure, but function returned ${result}`),
        (error) => expect(error).to.be.ok(),
    );
}

describe('Extended Security & Edge Case Tests', function() {
    this.timeout(10000);
    const password = "masterPassword#2024!";

    it('defends against swap attacks even without trustedDataCheck', async function() {
        const keychain = await Keychain.init(password);
        await keychain.set("https://bank.com", "superSecretBankPassword");
        await keychain.set("https://evil.com", "attackerPassword");

        const [repr, checksum] = await keychain.dump();
        const parsed = JSON.parse(repr);

        // Find keys
        const keys = Object.keys(parsed.kvs);
        expect(keys.length).to.equal(2);

        // Swap the ciphertext records
        const temp = parsed.kvs[keys[0]];
        parsed.kvs[keys[0]] = parsed.kvs[keys[1]];
        parsed.kvs[keys[1]] = temp;

        const tamperedRepr = JSON.stringify(parsed);

        // Load without trustedDataCheck
        const loadedKeychain = await Keychain.load(password, tamperedRepr);

        // Attempting to read either swapped domain must throw an error due to AEAD tag failure!
        await expectReject(loadedKeychain.get("https://bank.com"));
        await expectReject(loadedKeychain.get("https://evil.com"));
    });

    it('ensures ciphertexts have identical length regardless of password length (no length leakage)', async function() {
        const keychain = await Keychain.init(password);
        await keychain.set("site-short.com", "a");
        await keychain.set("site-medium.com", "mediumLength123");
        await keychain.set("site-max.com", "A".repeat(64));
        await keychain.set("site-empty.com", "");

        const [repr] = await keychain.dump();
        const parsed = JSON.parse(repr);

        const lengths = Object.values(parsed.kvs).map(val => (typeof val === 'string' ? val.length : JSON.stringify(val).length));
        const firstLength = lengths[0];
        for (const len of lengths) {
            expect(len).to.equal(firstLength);
        }
    });

    it('handles unicode, emojis, spaces, and punctuation correctly', async function() {
        const keychain = await Keychain.init(password);
        const specialDomain = "https://unicode-test.org/login?ref=1";
        const specialPassword = "P@$$w0rd with spaces & 🔒 emoji \u2764\uFE0F";
        
        await keychain.set(specialDomain, specialPassword);
        expect(await keychain.get(specialDomain)).to.equal(specialPassword);

        const [repr, checksum] = await keychain.dump();
        const restored = await Keychain.load(password, repr, checksum);
        expect(await restored.get(specialDomain)).to.equal(specialPassword);
    });

    it('rejects loading with wrong password even when trustedDataCheck is omitted', async function() {
        const keychain = await Keychain.init(password);
        await keychain.set("domain.com", "secret");
        const [repr] = await keychain.dump();

        await expectReject(Keychain.load("incorrect-master-password", repr));
    });

    it('updating an existing domain replaces value correctly', async function() {
        const keychain = await Keychain.init(password);
        await keychain.set("update-test.com", "initialPassword");
        expect(await keychain.get("update-test.com")).to.equal("initialPassword");

        await keychain.set("update-test.com", "newUpdatedPassword");
        expect(await keychain.get("update-test.com")).to.equal("newUpdatedPassword");

        const [repr] = await keychain.dump();
        const parsed = JSON.parse(repr);
        expect(Object.keys(parsed.kvs).length).to.equal(1);
    });

    it('removing a key and adding it again works cleanly', async function() {
        const keychain = await Keychain.init(password);
        await keychain.set("cycle.com", "pwd1");
        expect(await keychain.remove("cycle.com")).to.be(true);
        expect(await keychain.get("cycle.com")).to.be(null);
        expect(await keychain.remove("cycle.com")).to.be(false);

        await keychain.set("cycle.com", "pwd2");
        expect(await keychain.get("cycle.com")).to.equal("pwd2");
    });
});
