const crypto = require("crypto");
const { request } = require("./supabase");
const { clientIp } = require("./audit");

const COOKIE_NAME = "odak_session";

/*
 * Absolute session omru:
 * Giristen itibaren en fazla 8 saat.
 */
const SESSION_TTL_MS =
    8 * 60 * 60 * 1000;

/*
 * Idle timeout:
 * 60 dakika boyunca authenticated istek gelmezse
 * session gecersiz sayilir.
 */
const SESSION_IDLE_TIMEOUT_MS =
    60 * 60 * 1000;

/*
 * Her requestte Supabase'e PATCH atmamak icin
 * last_seen_at en fazla 5 dakikada bir guncellenir.
 */
const SESSION_TOUCH_INTERVAL_MS =
    5 * 60 * 1000;

function isProduction() {
    return process.env.NODE_ENV === "production";
}

function tokenHash(token) {
    return crypto
        .createHash("sha256")
        .update(String(token))
        .digest("hex");
}

function newToken() {
    return crypto
        .randomBytes(48)
        .toString("base64url");
}

function newSessionId() {
    return crypto.randomUUID();
}

function cookieOptions() {
    const production = isProduction();

    return {
        httpOnly: true,
        secure: production,
        sameSite: production ? "none" : "lax",
        path: "/",
        maxAge: SESSION_TTL_MS,
    };
}

function clearCookieOptions() {
    const production = isProduction();

    return {
        httpOnly: true,
        secure: production,
        sameSite: production ? "none" : "lax",
        path: "/",
    };
}

async function createSession({
    req,
    res,
    userKey,
}) {
    const token = newToken();
    const id = newSessionId();

    const now = new Date();

    const expiresAt = new Date(
        now.getTime() + SESSION_TTL_MS
    );

    const row = {
        id,
        user_key: String(userKey),
        token_hash: tokenHash(token),
        created_at: now.toISOString(),
        last_seen_at: now.toISOString(),
        expires_at: expiresAt.toISOString(),
        revoked_at: null,
        ip_address: clientIp(req),
        user_agent: String(
            req.headers["user-agent"] || ""
        ).slice(0, 500),
        revoke_reason: null,
    };

    await request("login_sessions", {
        method: "POST",
        headers: {
            Prefer: "return=minimal",
        },
        body: JSON.stringify(row),
    });

    res.cookie(
        COOKIE_NAME,
        token,
        cookieOptions()
    );

    return {
        id,
        expiresAt,
        expiresIn:
            Math.floor(
                SESSION_TTL_MS / 1000
            ),
    };
}

async function revokeSession(
    sessionId,
    reason = "logout"
) {
    if (!sessionId) return;

    await request(
        `login_sessions?id=eq.${encodeURIComponent(sessionId)}`,
        {
            method: "PATCH",
            headers: {
                Prefer: "return=minimal",
            },
            body: JSON.stringify({
                revoked_at:
                    new Date().toISOString(),
                revoke_reason:
                    String(reason).slice(0, 100),
            }),
        }
    );
}

async function getSessionByToken(token) {
    if (!token) return null;

    const hash = tokenHash(token);

    const rows = await request(
        `login_sessions?select=*&token_hash=eq.${encodeURIComponent(hash)}&limit=1`,
        {
            method: "GET",
        }
    );

    const session =
        Array.isArray(rows) && rows.length
            ? rows[0]
            : null;

    if (!session) {
        return null;
    }

    if (session.revoked_at) {
        return null;
    }

    const now = Date.now();

    const expiresAt =
        new Date(
            session.expires_at
        ).getTime();

    if (
        !Number.isFinite(expiresAt) ||
        expiresAt <= now
    ) {
        return null;
    }

    const lastSeenAt =
        new Date(
            session.last_seen_at ||
            session.created_at
        ).getTime();

    if (
        !Number.isFinite(lastSeenAt) ||
        now - lastSeenAt >
            SESSION_IDLE_TIMEOUT_MS
    ) {
        /*
         * DB'de de neden kapandigi gorunsun.
         * Cookie middleware tarafinda temizlenecek.
         */
        try {
            await revokeSession(
                session.id,
                "idle_timeout"
            );
        }
        catch (error) {
            console.error(
                "[SESSION IDLE REVOKE]",
                error?.message
            );
        }

        return null;
    }

    return session;
}

async function touchSession(session) {
    const lastSeen =
        new Date(
            session.last_seen_at ||
            session.created_at
        ).getTime();

    if (
        Number.isFinite(lastSeen) &&
        Date.now() - lastSeen <
            SESSION_TOUCH_INTERVAL_MS
    ) {
        return;
    }

    await request(
        `login_sessions?id=eq.${encodeURIComponent(session.id)}&revoked_at=is.null`,
        {
            method: "PATCH",
            headers: {
                Prefer: "return=minimal",
            },
            body: JSON.stringify({
                last_seen_at:
                    new Date().toISOString(),
            }),
        }
    );
}

async function revokeAllUserSessions(
    userKey,
    reason = "revoke_all"
) {
    if (
        userKey === undefined ||
        userKey === null
    ) {
        return;
    }

    await request(
        `login_sessions?user_key=eq.${encodeURIComponent(String(userKey))}&revoked_at=is.null`,
        {
            method: "PATCH",
            headers: {
                Prefer: "return=minimal",
            },
            body: JSON.stringify({
                revoked_at:
                    new Date().toISOString(),
                revoke_reason:
                    String(reason).slice(0, 100),
            }),
        }
    );
}

function clearSessionCookie(res) {
    res.clearCookie(
        COOKIE_NAME,
        clearCookieOptions()
    );
}

module.exports = {
    COOKIE_NAME,
    SESSION_TTL_MS,
    SESSION_IDLE_TIMEOUT_MS,
    createSession,
    getSessionByToken,
    touchSession,
    revokeSession,
    revokeAllUserSessions,
    clearSessionCookie,
};