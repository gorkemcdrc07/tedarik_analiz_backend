const fetch = require("node-fetch");
const { request } = require("./supabase");
const { decryptReelSecret } = require("./reelCrypto");

const TMS_BASE_URL = "https://tms.odaklojistik.com.tr";
const TEST_TMS_BASE_URL = "https://testtms.odaklojistik.com.tr";

const tokenCache = new Map();
const testTokenCache = new Map();
const TOKEN_FALLBACK_TTL_MS = 5 * 60 * 1000;
const TOKEN_SKEW_MS = 60 * 1000;

function getEnvironmentConfig(environment = "prod") {
    if (environment === "test") {
        return {
            baseUrl: TEST_TMS_BASE_URL,
            cache: testTokenCache,
        };
    }

    return {
        baseUrl: TMS_BASE_URL,
        cache: tokenCache,
    };
}
function extractToken(data) {
    return (
        data?.token ||
        data?.access_token ||
        data?.accessToken ||
        null
    );
}

function resolveExpiration(data) {
    let expiresAt =
        Date.now() + TOKEN_FALLBACK_TTL_MS;

    if (data?.expiration) {
        const parsed = new Date(data.expiration);

        if (!Number.isNaN(parsed.getTime())) {
            expiresAt = parsed.getTime();
        }
    }

    const expiresIn =
        data?.expires_in ??
        data?.expiresIn;

    if (expiresIn !== undefined) {
        const seconds = Number(expiresIn);

        if (
            Number.isFinite(seconds) &&
            seconds > 0
        ) {
            expiresAt =
                Date.now() + seconds * 1000;
        }
    }

    return expiresAt;
}

async function getReelCredentials(userKey) {
    const rows = await request(
        `Login?select=id,Reel_kullanici,Reel_sifre&id=eq.${encodeURIComponent(
            String(userKey)
        )}&limit=1`
    );

    const user =
        Array.isArray(rows) && rows.length
            ? rows[0]
            : null;

    if (!user) {
        const error =
            new Error("Kullanici bulunamadi.");
        error.status = 404;
        throw error;
    }

    const userName =
        String(user.Reel_kullanici || "").trim();

    const encryptedPassword =
        user.Reel_sifre;

    if (!userName || !encryptedPassword) {
        const error =
            new Error(
                "Reel/TMS kullanici bilgileri tanimli degil."
            );

        error.status = 409;
        throw error;
    }

    const password =
        decryptReelSecret(encryptedPassword);

    if (!password) {
        const error =
            new Error(
                "Reel/TMS sifresi cozumlenemedi."
            );

        error.status = 500;
        throw error;
    }

    return {
        userName,
        password,
    };
}

async function loginToTms(
    userKey,
    environment = "prod"
) {
    const {
        baseUrl,
        cache,
    } = getEnvironmentConfig(environment);

    const {
        userName,
        password,
    } = await getReelCredentials(userKey);

    const upstream = await fetch(
        `${baseUrl}/api/auth/login`,
        {
            method: "POST",
            headers: {
                "Content-Type":
                    "application/json",
            },
            body: JSON.stringify({
                userName,
                password,
            }),
        }
    );

    const text = await upstream.text();

    let data = {};

    try {
        data = text ? JSON.parse(text) : {};
    } catch {
        data = {};
    }

    if (!upstream.ok) {
        const error =
            new Error(
                `TMS kimlik dogrulama basarisiz (${upstream.status}).`
            );

        error.status = 502;
        throw error;
    }

    const token = extractToken(data);

    if (!token) {
        const error =
            new Error(
                "TMS login yanitinda token bulunamadi."
            );

        error.status = 502;
        throw error;
    }

    const expiresAt =
        resolveExpiration(data);

    cache.set(
        String(userKey),
        {
            token,
            expiresAt,
        }
    );

    return token;
}

async function getTmsToken(
    userKey,
    {
        forceRefresh = false,
        environment = "prod",
    } = {}
) {
    const key = String(userKey);

    const {
        cache,
    } = getEnvironmentConfig(environment);

    if (!forceRefresh) {
        const cached =
            cache.get(key);

        if (
            cached?.token &&
            cached?.expiresAt &&
            Date.now() <
                cached.expiresAt -
                    TOKEN_SKEW_MS
        ) {
            return cached.token;
        }
    }

    return loginToTms(
        key,
        environment
    );
}

function invalidateTmsToken(
    userKey,
    environment = "prod"
) {
    const {
        cache,
    } = getEnvironmentConfig(environment);

    cache.delete(
        String(userKey)
    );
}

async function tmsFetch(
    userKey,
    path,
    init = {},
    {
        environment = "prod",
    } = {}
) {
    const {
        baseUrl,
    } = getEnvironmentConfig(environment);

    const execute = async (
        forceRefresh = false
    ) => {
        const token =
            await getTmsToken(
                userKey,
                {
                    forceRefresh,
                    environment,
                }
            );

        const headers = {
            ...(init.headers || {}),
            Authorization:
                `Bearer ${token}`,
        };

        return fetch(
            `${baseUrl}${path}`,
            {
                ...init,
                headers,
            }
        );
    };

    let response =
        await execute(false);

    if (response.status === 401) {
        invalidateTmsToken(
            userKey,
            environment
        );

        response =
            await execute(true);
    }

    return response;
}


/*
 * TMS ORDER SERVICE ACCOUNT
 *
 * Siparis olusturma islemleri icin kullanilan
 * server-side TMS hesabi.
 *
 * Credential degerleri sadece environment
 * variable uzerinden okunur.
 */

let orderTokenCache = null;

function getOrderCredentials() {
    const userName = String(
        process.env.TMS_ORDER_USERNAME || ""
    ).trim();

    const password = String(
        process.env.TMS_ORDER_PASSWORD || ""
    );

    if (!userName || !password) {
        const err = new Error(
            "TMS siparis servis hesabi yapilandirilmamis."
        );

        err.status = 503;
        throw err;
    }

    return {
        userName,
        password,
    };
}

function invalidateOrderTmsToken() {
    orderTokenCache = null;
}

async function getOrderTmsToken({
    forceRefresh = false,
} = {}) {
    if (
        !forceRefresh &&
        orderTokenCache?.token &&
        orderTokenCache?.expiresAt &&
        Date.now() <
            orderTokenCache.expiresAt -
                TOKEN_SKEW_MS
    ) {
        return orderTokenCache.token;
    }

    const credentials =
        getOrderCredentials();

    const response = await fetch(
        "https://tms.odaklojistik.com.tr/api/auth/login",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
            },
            body: JSON.stringify(
                credentials
            ),
        }
    );

    const text = await response.text();

    if (!response.ok) {
        const err = new Error(
            "TMS siparis servis hesabi login basarisiz (" +
            response.status +
            ")."
        );

        err.status = 502;
        throw err;
    }

    let data;

    try {
        data = JSON.parse(text);
    } catch {
        const err = new Error(
            "TMS siparis login cevabi gecersiz."
        );

        err.status = 502;
        throw err;
    }

    const token =
        data?.token ||
        data?.accessToken ||
        data?.access_token ||
        data?.Token ||
        data?.AccessToken;

    if (!token) {
        const err = new Error(
            "TMS siparis login cevabinda token bulunamadi."
        );

        err.status = 502;
        throw err;
    }

    let expiresAt =
        Date.now() + 30 * 60 * 1000;

    try {
        const parts =
            String(token).split(".");

        if (parts.length === 3) {
            const payload = JSON.parse(
                Buffer.from(
                    parts[1],
                    "base64url"
                ).toString("utf8")
            );

            if (
                Number.isFinite(
                    Number(payload?.exp)
                )
            ) {
                expiresAt =
                    Number(payload.exp) *
                    1000;
            }
        }
    } catch {
        // JWT okunamazsa varsayilan
        // cache suresi kullanilir.
    }

    orderTokenCache = {
        token,
        expiresAt,
    };

    return token;
}

async function tmsOrderFetch(
    path,
    init = {}
) {
    const execute = async (
        forceRefresh = false
    ) => {
        const token =
            await getOrderTmsToken({
                forceRefresh,
            });

        return fetch(
            "https://tms.odaklojistik.com.tr" +
                path,
            {
                ...init,
                headers: {
                    ...(init.headers || {}),
                    Authorization:
                        "Bearer " + token,
                },
            }
        );
    };

    let response =
        await execute(false);

    if (response.status === 401) {
        invalidateOrderTmsToken();

        response =
            await execute(true);
    }

    return response;
}

module.exports = {
    getTmsToken,
    invalidateTmsToken,
    tmsFetch,
    getOrderTmsToken,
    invalidateOrderTmsToken,
    tmsOrderFetch,
};