const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const QRCode = require("qrcode");

const {
    createSession,
    SESSION_TTL_MS,
} = require("./auth/session");

const {
    writeSecurityEvent,
} = require("./auth/audit");

const {
    loginStartLimiter,
    totpVerifyLimiter,
} = require("./auth/rateLimit");

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MAX_VERIFY_ATTEMPTS = 5;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCK_MS = 15 * 60 * 1000;

const challenges = new Map();
const loginAttempts = new Map();

let otplibPromise = null;

function getOtplib() {
    if (!otplibPromise) {
        otplibPromise = import("otplib");
    }
    return otplibPromise;
}

function config() {
    return {
        supabaseUrl: String(process.env.SUPABASE_URL || "").replace(/\/+$/, ""),
        supabaseKey: String(process.env.SUPABASE_SERVICE_ROLE_KEY || ""),
        encryptionKey: String(process.env.TOTP_ENCRYPTION_KEY || ""),
    };
}

function getEncryptionKey() {
    const { encryptionKey } = config();

    if (!encryptionKey) {
        throw new Error("TOTP_ENCRYPTION_KEY tanÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±mlÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± deÃƒÆ’Ã¢â‚¬ÂÃƒâ€¦Ã‚Â¸il.");
    }

    const key = Buffer.from(encryptionKey, "base64");

    if (key.length !== 32) {
        throw new Error(
            "TOTP_ENCRYPTION_KEY Base64 olarak tam 32 byte olmalÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±dÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±r."
        );
    }

    return key;
}


function encryptSecret(secret) {
    const key = getEncryptionKey();
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(
        "aes-256-gcm",
        key,
        iv
    );

    const ciphertext = Buffer.concat([
        cipher.update(secret, "utf8"),
        cipher.final(),
    ]);

    const tag = cipher.getAuthTag();

    return [
        "v1",
        iv.toString("base64url"),
        tag.toString("base64url"),
        ciphertext.toString("base64url"),
    ].join(".");
}

function decryptSecret(value) {
    if (!value || typeof value !== "string") {
        throw new Error("TOTP secret bulunamadÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±.");
    }

    const parts = value.split(".");

    if (parts.length !== 4 || parts[0] !== "v1") {
        throw new Error("TOTP secret formatÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± geÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ersiz.");
    }

    const [, ivPart, tagPart, ciphertextPart] = parts;

    const iv = Buffer.from(ivPart, "base64url");
    const tag = Buffer.from(tagPart, "base64url");
    const ciphertext = Buffer.from(
        ciphertextPart,
        "base64url"
    );

    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        getEncryptionKey(),
        iv
    );

    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
    ]);

    return plaintext.toString("utf8");
}

function cleanupExpiredState() {
    const now = Date.now();

    for (const [id, challenge] of challenges.entries()) {
        if (challenge.expiresAt <= now) {
            challenges.delete(id);
        }
    }

    for (const [key, state] of loginAttempts.entries()) {
        if (
            state.lockedUntil &&
            state.lockedUntil <= now
        ) {
            loginAttempts.delete(key);
        }
    }
}

function normalizeUsername(value) {
    return String(value || "").trim();
}

function attemptKey(username, req) {
    const ip =
        req.ip ||
        req.socket?.remoteAddress ||
        "unknown";

    return `${normalizeUsername(username).toLowerCase()}:${ip}`;
}

function checkLoginLock(key) {
    const state = loginAttempts.get(key);

    if (!state) {
        return null;
    }

    if (
        state.lockedUntil &&
        state.lockedUntil > Date.now()
    ) {
        return state.lockedUntil;
    }

    if (
        state.lockedUntil &&
        state.lockedUntil <= Date.now()
    ) {
        loginAttempts.delete(key);
    }

    return null;
}

function recordLoginFailure(key) {
    const current = loginAttempts.get(key) || {
        count: 0,
        lockedUntil: null,
    };

    current.count += 1;

    if (current.count >= MAX_LOGIN_ATTEMPTS) {
        current.lockedUntil =
            Date.now() + LOGIN_LOCK_MS;
        current.count = 0;
    }

    loginAttempts.set(key, current);

    return current.lockedUntil;
}

function clearLoginFailures(key) {
    loginAttempts.delete(key);
}

function safeUser(user) {
    return {
        id: user.id,
        kullanici: user.kullanici,
        kullanici_adi: user.kullanici_adi,
        rol: user.rol,
        allowedScreens: user.allowedScreens,
        allowedButtons: user.allowedButtons,
    };
}

function isUserActive(user) {
    if (user.aktif === undefined || user.aktif === null) {
        return true;
    }

    if (typeof user.aktif === "boolean") {
        return user.aktif;
    }

    const value = String(user.aktif)
        .trim()
        .toLowerCase();

    return ![
        "false",
        "0",
        "hayir",
        "hayÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±r",
        "pasif",
        "inactive",
    ].includes(value);
}


async function supabaseRequest(
    path,
    {
        method = "GET",
        body,
        headers = {},
    } = {}
) {
    const { supabaseUrl, supabaseKey } = config();

    if (!supabaseUrl || !supabaseKey) {
        throw new Error(
            "Supabase sunucu ayarlarÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± eksik."
        );
    }

    const response = await fetch(
        `${supabaseUrl}${path}`,
        {
            method,
            headers: {
                apikey: supabaseKey,
                Authorization:
                    `Bearer ${supabaseKey}`,
                "Content-Type":
                    "application/json",
                ...headers,
            },
            body:
                body === undefined
                    ? undefined
                    : JSON.stringify(body),
        }
    );

    const raw = await response.text();

    let data = null;

    if (raw) {
        try {
            data = JSON.parse(raw);
        } catch {
            data = raw;
        }
    }

    if (!response.ok) {
        const detail =
            typeof data === "string"
                ? data
                : JSON.stringify(data);

        throw new Error(
            `Supabase isteÃƒÆ’Ã¢â‚¬ÂÃƒâ€¦Ã‚Â¸i baÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸arÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±sÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±z (${response.status}): ${detail}`
        );
    }

    return {
        status: response.status,
        data,
    };
}

async function getLoginUser(username) {
    const { supabaseUrl, supabaseKey } = config();

    if (!supabaseUrl || !supabaseKey) {
        throw new Error(
            "Supabase sunucu ayarlarÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± eksik."
        );
    }

    const endpoint = new URL(
        `${supabaseUrl}/rest/v1/Login`
    );

    endpoint.searchParams.set("select", "*");
    endpoint.searchParams.set(
        "kullanici_adi",
        `eq.${username}`
    );
    endpoint.searchParams.set("limit", "1");

    const response = await fetch(
        endpoint.toString(),
        {
            headers: {
                apikey: supabaseKey,
                Authorization:
                    `Bearer ${supabaseKey}`,
            },
        }
    );

    const raw = await response.text();

    if (!response.ok) {
        throw new Error(
            `Login tablosu okunamadÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± (${response.status}): ${raw}`
        );
    }

    let rows;

    try {
        rows = JSON.parse(raw);
    } catch {
        throw new Error(
            "Login tablosundan geÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ersiz yanÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±t alÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±ndÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±."
        );
    }

    return Array.isArray(rows) && rows.length
        ? rows[0]
        : null;
}

async function getTotpRecord(userKey) {
    const query =
        `/rest/v1/login_totp` +
        `?user_key=eq.${encodeURIComponent(userKey)}` +
        `&select=*` +
        `&limit=1`;

    const { data } =
        await supabaseRequest(query);

    return Array.isArray(data) && data.length
        ? data[0]
        : null;
}

async function upsertTotpRecord(record) {
    await supabaseRequest(
        "/rest/v1/login_totp?on_conflict=user_key",
        {
            method: "POST",
            headers: {
                Prefer:
                    "resolution=merge-duplicates,return=minimal",
            },
            body: record,
        }
    );
}

async function updateTotpRecord(
    userKey,
    values
) {
    await supabaseRequest(
        `/rest/v1/login_totp?user_key=eq.${encodeURIComponent(
            userKey
        )}`,
        {
            method: "PATCH",
            headers: {
                Prefer: "return=minimal",
            },
            body: {
                ...values,
                updated_at:
                    new Date().toISOString(),
            },
        }
    );
}

function createChallenge(user, mode) {
    const challengeId =
        crypto.randomBytes(32).toString("base64url");

    const challenge = {
        id: challengeId,
        user: safeUser(user),
        userKey: String(user.id),
        mode,
        attempts: 0,
        createdAt: Date.now(),
        expiresAt:
            Date.now() + CHALLENGE_TTL_MS,
    };

    challenges.set(
        challengeId,
        challenge
    );

    return challenge;
}

async function createTotpSetup(user) {
    const { generateSecret, generateURI } =
        await getOtplib();

    const secret = generateSecret();

    const encryptedSecret =
        encryptSecret(secret);

    const userKey = String(user.id);

    await upsertTotpRecord({
        user_key: userKey,
        secret_enc: encryptedSecret,
        enabled: false,
        verified_at: null,
        last_used_step: null,
        updated_at:
            new Date().toISOString(),
    });

    const label =
        user.kullanici_adi ||
        user.kullanici ||
        `user-${userKey}`;

    const uri = generateURI({
        issuer: "Odak Lojistik",
        label,
        secret,
    });

    const qrCodeDataUrl =
        await QRCode.toDataURL(uri, {
            errorCorrectionLevel: "M",
            margin: 2,
            width: 320,
        });

    const challenge =
        createChallenge(user, "setup");

    /*
     * URI veya secret kesinlikle response'a
     * ayrÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±ca gÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¶nderilmiyor.
     * Secret yalnÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±zca QR'ÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±n iÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§inde bulunuyor.
     */
    return {
        challenge,
        qrCodeDataUrl,
    };
}

async function verifyTotp(
    secret,
    token,
    lastUsedStep
) {
    const { verify } = await getOtplib();

    const options = {
        secret,
        token,
        algorithm: "sha1",
        digits: 6,
        period: 30,

        /*
         * Telefon/sunucu saatindeki kÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼k
         * sapmalar iÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§in ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â±30 saniye.
         */
        epochTolerance: 30,
    };

    /*
     * otplib v13 replay korumasÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±.
     */
    if (
        lastUsedStep !== null &&
        lastUsedStep !== undefined
    ) {
        options.afterTimeStep =
            Number(lastUsedStep);
    }

    return verify(options);
}

function validateCode(value) {
    const code = String(value || "")
        .replace(/\s+/g, "");

    if (!/^\d{6}$/.test(code)) {
        return null;
    }

    return code;
}

function install(app) {
    if (!app) {
        throw new Error(
            "Express app gerekli."
        );
    }

    app.get(
        "/api/auth/2fa/health",
        async (_req, res) => {
            try {
                getEncryptionKey();

                const { supabaseUrl, supabaseKey } =
                    config();

                return res.json({
                    ok: true,
                    service: "totp-authenticator",
                    provider: "totp",
                    supabaseConfigured: Boolean(
                        supabaseUrl &&
                            supabaseKey
                    ),
                    encryptionConfigured: true,
                    challengeExpiresIn:
                        CHALLENGE_TTL_MS / 1000,
                    sessionExpiresIn:
                        SESSION_TTL_MS / 1000,
                    issuer: "Odak Lojistik",
                });
            } catch (error) {
                return res.status(503).json({
                    ok: false,
                    provider: "totp",
                    error: error.message,
                });
            }
        }
    );

    app.post(
        "/api/auth/2fa/start",
        loginStartLimiter,
        async (req, res) => {
            cleanupExpiredState();

            const username =
                normalizeUsername(
                    req.body?.username
                );

            const password =
                String(
                    req.body?.password || ""
                );

            if (!username || !password) {
                return res.status(400).json({
                    error:
                        "KullanÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±cÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± adÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± ve ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸ifre zorunludur.",
                });
            }

            const key =
                attemptKey(username, req);

            const lockedUntil =
                checkLoginLock(key);

            if (lockedUntil) {
                const retryAfter =
                    Math.max(
                        1,
                        Math.ceil(
                            (lockedUntil -
                                Date.now()) /
                                1000
                        )
                    );

                res.set(
                    "Retry-After",
                    String(retryAfter)
                );

                await writeSecurityEvent({
                    req,
                    userKey: null,
                    eventType:
                        "LOGIN_LOCKED",
                    success: false,
                    metadata: {
                        username:
                            username
                                .toLowerCase()
                                .slice(0, 200),
                        reason:
                            "account_lock_active",
                        retryAfter,
                    },
                });

                return res.status(429).json({
                    error:
                        "ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¡ok fazla baÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸arÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±sÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±z giriÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸ denemesi. LÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼tfen daha sonra tekrar deneyin.",
                    retryAfter,
                });
            }

            try {
                const user =
                    await getLoginUser(username);

                /*
                 * KullanÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±cÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± bulunamadÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± / ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸ifre yanlÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸
                 * ayrÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±mÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±nÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± dÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸arÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± vermiyoruz.
                 */
                if (
                    !user ||
                    !(
                    typeof user.password_hash === "string" &&
                    /^\$2[aby]\$\d{2}\$/.test(user.password_hash) &&
                    await bcrypt.compare(
                        password,
                        user.password_hash
                    )
                )
                ) {
                    const lockedAfterFailure =
                        recordLoginFailure(key);

                    await writeSecurityEvent({
                        req,
                        userKey:
                            user?.id === undefined ||
                            user?.id === null
                                ? null
                                : String(user.id),
                        eventType:
                            lockedAfterFailure
                                ? "LOGIN_LOCKED"
                                : "LOGIN_FAILED",
                        success: false,
                        metadata: {
                            username:
                                username
                                    .toLowerCase()
                                    .slice(0, 200),
                            reason:
                                "invalid_credentials",
                        },
                    });

                    if (lockedAfterFailure) {
                        const retryAfter =
                            Math.max(
                                1,
                                Math.ceil(
                                    (
                                        lockedAfterFailure -
                                        Date.now()
                                    ) /
                                        1000
                                )
                            );

                        res.set(
                            "Retry-After",
                            String(retryAfter)
                        );

                        return res.status(429).json({
                            error:
                                "Cok fazla basarisiz giris denemesi. Lutfen daha sonra tekrar deneyin.",
                            retryAfter,
                        });
                    }

                    return res.status(401).json({
                        error:
                            "KullanÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±cÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± adÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± veya ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸ifre hatalÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±.",
                    });
                }

                if (!isUserActive(user)) {
                    const lockedAfterFailure =
                        recordLoginFailure(key);

                    await writeSecurityEvent({
                        req,
                        userKey:
                            String(user.id),
                        eventType:
                            lockedAfterFailure
                                ? "LOGIN_LOCKED"
                                : "LOGIN_FAILED",
                        success: false,
                        metadata: {
                            username:
                                username
                                    .toLowerCase()
                                    .slice(0, 200),
                            reason:
                                "inactive_user",
                        },
                    });

                    if (lockedAfterFailure) {
                        const retryAfter =
                            Math.max(
                                1,
                                Math.ceil(
                                    (
                                        lockedAfterFailure -
                                        Date.now()
                                    ) /
                                        1000
                                )
                            );

                        res.set(
                            "Retry-After",
                            String(retryAfter)
                        );

                        return res.status(429).json({
                            error:
                                "Cok fazla basarisiz giris denemesi. Lutfen daha sonra tekrar deneyin.",
                            retryAfter,
                        });
                    }

                    return res.status(403).json({
                        error:
                            "Bu kullanÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±cÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± hesabÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± aktif deÃƒÆ’Ã¢â‚¬ÂÃƒâ€¦Ã‚Â¸il.",
                    });
                }

                if (
                    user.id === undefined ||
                    user.id === null ||
                    String(user.id).trim() === ""
                ) {
                    return res.status(500).json({
                        error:
                            "KullanÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±cÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± iÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§in geÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§erli bir kimlik bulunamadÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±.",
                    });
                }

                clearLoginFailures(key);

                const userKey =
                    String(user.id);

                const totpRecord =
                    await getTotpRecord(
                        userKey
                    );

                /*
                 * TOTP zaten kurulmuÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸sa QR ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼retme.
                 */
                if (
                    totpRecord &&
                    totpRecord.enabled
                ) {
                    const challenge =
                        createChallenge(
                            user,
                            "verify"
                        );

                    return res.json({
                        ok: true,
                        mode: "verify",
                        challengeId:
                            challenge.id,
                        expiresIn:
                            CHALLENGE_TTL_MS /
                            1000,
                        message:
                            "Authenticator uygulamanÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±zdaki 6 haneli kodu girin.",
                    });
                }

                /*
                 * ÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â°lk kurulum veya yarÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±m kalmÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸
                 * kurulum: yeni secret ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼ret.
                 */
                const {
                    challenge,
                    qrCodeDataUrl,
                } = await createTotpSetup(
                    user
                );

                return res.json({
                    ok: true,
                    mode: "setup",
                    challengeId:
                        challenge.id,
                    qrCodeDataUrl,
                    expiresIn:
                        CHALLENGE_TTL_MS /
                        1000,
                    message:
                        "QR kodunu Microsoft Authenticator veya Google Authenticator ile okutun ve oluÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸an 6 haneli kodu girin.",
                });
            } catch (error) {
                console.error(
                    "[TOTP START]",
                    error?.message ||
                        "Bilinmeyen hata"
                );

                return res.status(500).json({
                    error:
                        "ÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â°ki aÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸amalÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± doÃƒÆ’Ã¢â‚¬ÂÃƒâ€¦Ã‚Â¸rulama baÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸latÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±lamadÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±.",
                });
            }
        }
    );

    app.post(
        "/api/auth/2fa/verify",
        totpVerifyLimiter,
        async (req, res) => {
            cleanupExpiredState();

            const challengeId =
                String(
                    req.body?.challengeId ||
                        ""
                ).trim();

            const code =
                validateCode(
                    req.body?.code
                );

            if (!challengeId || !code) {
                return res.status(400).json({
                    error:
                        "DoÃƒÆ’Ã¢â‚¬ÂÃƒâ€¦Ã‚Â¸rulama bilgileri eksik veya kod geÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ersiz.",
                });
            }

            const challenge =
                challenges.get(
                    challengeId
                );

            if (!challenge) {
                return res.status(410).json({
                    error:
                        "DoÃƒÆ’Ã¢â‚¬ÂÃƒâ€¦Ã‚Â¸rulama oturumu bulunamadÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± veya sÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼resi doldu.",
                });
            }

            if (
                challenge.expiresAt <=
                Date.now()
            ) {
                challenges.delete(
                    challengeId
                );

                return res.status(410).json({
                    error:
                        "DoÃƒÆ’Ã¢â‚¬ÂÃƒâ€¦Ã‚Â¸rulama sÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼resi doldu. LÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼tfen yeniden giriÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸ yapÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±n.",
                });
            }


            try {
                const record =
                    await getTotpRecord(
                        challenge.userKey
                    );

                if (
                    !record ||
                    !record.secret_enc
                ) {
                    challenges.delete(
                        challengeId
                    );

                    return res.status(409).json({
                        error:
                            "Authenticator kaydÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± bulunamadÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±. LÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼tfen kurulumu yeniden baÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸latÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±n.",
                    });
                }

                /*
                 * Challenge setup iken DB'de enabled
                 * olmamalÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±; verify iken enabled olmalÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±.
                 * BÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¶ylece eski/stale challenge'lar
                 * kullanÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±lamaz.
                 */
                if (
                    challenge.mode ===
                        "verify" &&
                    !record.enabled
                ) {
                    challenges.delete(
                        challengeId
                    );

                    return res.status(409).json({
                        error:
                            "Authenticator kurulumu tamamlanmamÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸.",
                    });
                }

                if (
                    challenge.mode ===
                        "setup" &&
                    record.enabled
                ) {
                    challenges.delete(
                        challengeId
                    );

                    return res.status(409).json({
                        error:
                            "Authenticator zaten etkinleÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸tirilmiÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸. LÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼tfen yeniden giriÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€¦Ã‚Â¸ yapÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±n.",
                    });
                }

                const secret =
                    decryptSecret(
                        record.secret_enc
                    );

                const result =
                    await verifyTotp(
                        secret,
                        code,
                        record.last_used_step
                    );

                if (!result.valid) {
                    challenge.attempts += 1;

                    const attemptsRemaining =
                        Math.max(
                            0,
                            MAX_VERIFY_ATTEMPTS -
                                challenge.attempts
                        );

                    const isLocked =
                        challenge.attempts >=
                        MAX_VERIFY_ATTEMPTS;

                    await writeSecurityEvent({
                        req,
                        userKey:
                            challenge.userKey,
                        eventType:
                            isLocked
                                ? "TOTP_LOCKED"
                                : "TOTP_FAILED",
                        success: false,
                        metadata: {
                            mode:
                                challenge.mode,
                            attemptsRemaining,
                            reason:
                                "invalid_totp",
                        },
                    });

                    if (isLocked) {
                        challenges.delete(
                            challengeId
                        );

                        return res.status(429).json({
                            error:
                                "Cok fazla hatali dogrulama denemesi. Lutfen yeniden giris yapin.",
                            attemptsRemaining: 0,
                        });
                    }

                    return res.status(401).json({
                        error:
                            "Authenticator kodu hatali veya suresi dolmus.",
                        attemptsRemaining,
                    });
                }
                /*
                 * otplib v13 doÃƒÆ’Ã¢â‚¬ÂÃƒâ€¦Ã‚Â¸rulanan timeStep'i
                 * dÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¶ndÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼rÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼r. Bunu kaydedip aynÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±
                 * OTP'nin tekrar kullanÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±mÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±nÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¶nlÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¼yoruz.
                 */
                const matchedTimeStep =
                    result.timeStep;

                if (
                    matchedTimeStep ===
                        undefined ||
                    matchedTimeStep === null
                ) {
                    throw new Error(
                        "TOTP timeStep alÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±namadÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±."
                    );
                }

                await updateTotpRecord(
                    challenge.userKey,
                    {
                        enabled: true,
                        verified_at:
                            challenge.mode ===
                            "setup"
                                ? new Date().toISOString()
                                : record.verified_at,
                        last_used_step:
                            matchedTimeStep,
                    }
                );

                challenges.delete(
                    challengeId
                );

                const user =
                    challenge.user;

                const session =
                    await createSession({
                        req,
                        res,
                        userKey:
                            challenge.userKey,
                    });

                await writeSecurityEvent({
                    req,
                    userKey:
                        challenge.userKey,
                    eventType:
                        "LOGIN_SUCCESS",
                    success: true,
                    metadata: {
                        mode:
                            challenge.mode,
                    },
                });

                return res.json({
                    ok: true,
                    mode:
                        challenge.mode,
                    user,
                    expiresIn:
                        session.expiresIn,
                });
            } catch (error) {
                console.error(
                    "[TOTP VERIFY]",
                    error?.message ||
                        "Bilinmeyen hata"
                );

                return res.status(500).json({
                    error:
                        "Authenticator doÃƒÆ’Ã¢â‚¬ÂÃƒâ€¦Ã‚Â¸rulamasÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â± tamamlanamadÃƒÆ’Ã¢â‚¬ÂÃƒâ€šÃ‚Â±.",
                });
            }
        }
    );

    console.log(
        "[2FA] TOTP Authenticator aktif."
    );
}

module.exports = {
    install,
};