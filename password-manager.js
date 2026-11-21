"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor() {
    this.kvs = {};
    this.data = { 
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      kvs: this.kvs,
      salt: null,
      authTag: null
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      domainMacKey: null,
      aesKey: null
    };
  };

  // Derives the master HMAC key from password + salt via PBKDF2, then derives sub-keys
  static async _deriveKeys(password, salt) {
    const rawKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      rawKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"]
    );

    // Derive domain MAC key
    const domainKeyMaterial = await subtle.sign("HMAC", masterKey, stringToBuffer("domain-mac-key"));
    const domainMacKey = await subtle.importKey(
      "raw",
      domainKeyMaterial,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    // Derive AES-GCM encryption key
    const aesKeyMaterial = await subtle.sign("HMAC", masterKey, stringToBuffer("aes-gcm-key"));
    const aesKey = await subtle.importKey(
      "raw",
      aesKeyMaterial,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );

    // Derive auth verification tag for password validation on load
    const authCheck = await subtle.sign("HMAC", masterKey, stringToBuffer("auth-verification-tag"));
    const authTag = encodeBuffer(authCheck);

    return { domainMacKey, aesKey, authTag };
  }

  // Pads password to 258 bytes (2-byte length prefix + UTF-8 bytes + zeros)
  static _pad(str) {
    const buf = stringToBuffer(str);
    const padded = Buffer.alloc(258, 0);
    padded.writeUInt16BE(buf.length, 0);
    buf.copy(padded, 2);
    return padded;
  }

  static _unpad(buf) {
    const len = buf.readUInt16BE(0);
    if (len > buf.length - 2) {
      throw new Error("Tampered or invalid padding");
    }
    return bufferToString(buf.subarray(2, 2 + len));
  }

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    const keychain = new Keychain();
    const salt = getRandomBytes(16);
    const keys = await Keychain._deriveKeys(password, salt);

    keychain.data.salt = encodeBuffer(salt);
    keychain.data.authTag = keys.authTag;
    keychain.secrets.domainMacKey = keys.domainMacKey;
    keychain.secrets.aesKey = keys.aesKey;

    return keychain;
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    if (trustedDataCheck !== undefined) {
      const hash = encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr)));
      if (hash !== trustedDataCheck) {
        throw new Error("Integrity check failed: trusted checksum mismatch");
      }
    }

    let dumpObj;
    try {
      dumpObj = JSON.parse(repr);
    } catch (e) {
      throw new Error("Invalid serialized representation");
    }

    if (!dumpObj || typeof dumpObj !== 'object' || !dumpObj.salt || !dumpObj.authTag || !dumpObj.kvs) {
      throw new Error("Malformed keychain data structure");
    }

    const salt = decodeBuffer(dumpObj.salt);
    const keys = await Keychain._deriveKeys(password, salt);

    if (keys.authTag !== dumpObj.authTag) {
      throw new Error("Invalid password");
    }

    const keychain = new Keychain();
    keychain.kvs = dumpObj.kvs;
    keychain.data.kvs = dumpObj.kvs;
    keychain.data.salt = dumpObj.salt;
    keychain.data.authTag = dumpObj.authTag;
    keychain.secrets.domainMacKey = keys.domainMacKey;
    keychain.secrets.aesKey = keys.aesKey;

    return keychain;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    const repr = JSON.stringify({
      kvs: this.kvs,
      salt: this.data.salt,
      authTag: this.data.authTag
    });
    const checksum = encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr)));
    return [repr, checksum];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    const domainTag = encodeBuffer(await subtle.sign("HMAC", this.secrets.domainMacKey, stringToBuffer(name)));
    if (!Object.prototype.hasOwnProperty.call(this.kvs, domainTag)) {
      return null;
    }

    const entry = this.kvs[domainTag];
    let iv, ct;
    if (typeof entry === 'string') {
      const buf = decodeBuffer(entry);
      iv = buf.subarray(0, 12);
      ct = buf.subarray(12);
    } else if (typeof entry === 'object' && entry !== null) {
      iv = decodeBuffer(entry.iv);
      ct = decodeBuffer(entry.ciphertext || entry.contents || entry.ct);
    } else {
      throw new Error("Corrupted entry in KVS");
    }

    let decrypted;
    try {
      decrypted = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv,
          additionalData: stringToBuffer(name)
        },
        this.secrets.aesKey,
        ct
      );
    } catch (e) {
      throw new Error("Decryption failed: swap attack or tampered record");
    }

    return Keychain._unpad(Buffer.from(decrypted));
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    const domainTag = encodeBuffer(await subtle.sign("HMAC", this.secrets.domainMacKey, stringToBuffer(name)));
    const padded = Keychain._pad(value);
    const iv = getRandomBytes(12);

    const ct = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        additionalData: stringToBuffer(name)
      },
      this.secrets.aesKey,
      padded
    );

    this.kvs[domainTag] = encodeBuffer(Buffer.concat([iv, Buffer.from(ct)]));
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    const domainTag = encodeBuffer(await subtle.sign("HMAC", this.secrets.domainMacKey, stringToBuffer(name)));
    if (Object.prototype.hasOwnProperty.call(this.kvs, domainTag)) {
      delete this.kvs[domainTag];
      return true;
    }
    return false;
  };
};

module.exports = { Keychain };
