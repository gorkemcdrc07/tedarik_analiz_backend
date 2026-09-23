const crypto = require("crypto");

const PREFIX = "reel.v1";

function getKey() {
    const raw = String(
        process.env.REEL_ENCRYPTION_KEY || ""
    ).trim();

    if (!raw) {
        throw new Error(
            "REEL_ENCRYPTION_KEY tanimli degil."
        );
    }

    let key;

    try {
        key = Buffer.from(raw, "base64");
    } catch {
        throw new Error(
            "REEL_ENCRYPTION_KEY Base64 olmali."
        );
    }

    if (key.length !== 32) {
        throw new Error(
            "REEL_ENCRYPTION_KEY 32 byte olmali."
        );
    }

    return key;
}

function isEncrypted(value) {
    return (
        typeof value === "string" &&
        value.startsWith(`${PREFIX}.`)
    );
}

function encryptReelSecret(value) {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return null;
    }

    const plaintext = String(value);

    if (isEncrypted(plaintext)) {
        return plaintext;
    }

    const key = getKey();
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(
        "aes-256-gcm",
        key,
        iv
    );

    const ciphertext = Buffer.concat([
        cipher.update(
            plaintext,
            "utf8"
        ),
        cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    return [
        PREFIX,
        iv.toString("base64url"),
        tag.toString("base64url"),
        ciphertext.toString("base64url")
    ].join(".");
}

function decryptReelSecret(value) {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return null;
    }

    const encoded = String(value);

    /*
     * Migration doneminde mevcut plaintext
     * kayitlar okunabilir.
     *
     * Tum veriler AES-GCM'e tasindiktan sonra
     * bu fallback kaldirilacak.
     */
    if (!isEncrypted(encoded)) {
        return encoded;
    }

    const parts = encoded.split(".");

    if (
        parts.length !== 5 ||
        parts[0] !== "reel" ||
        parts[1] !== "v1"
    ) {
        throw new Error(
            "Gecersiz Reel credential formati."
        );
    }

    const iv = Buffer.from(
        parts[2],
        "base64url"
    );

    const tag = Buffer.from(
        parts[3],
        "base64url"
    );

    const ciphertext = Buffer.from(
        parts[4],
        "base64url"
    );

    if (iv.length !== 12 || tag.length !== 16) {
        throw new Error(
            "Gecersiz Reel credential verisi."
        );
    }

    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        getKey(),
        iv
    );

    decipher.setAuthTag(tag);

    return Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]).toString("utf8");
}

module.exports = {
    encryptReelSecret,
    decryptReelSecret,
    isEncrypted
};