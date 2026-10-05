const { request } = require("./supabase");

function clientIp(req) {
    const forwarded = req.headers["x-forwarded-for"];

    if (forwarded) {
        return String(forwarded)
            .split(",")[0]
            .trim()
            .slice(0, 100);
    }

    return String(
        req.ip ||
        req.socket?.remoteAddress ||
        ""
    ).slice(0, 100);
}

function sanitizeMetadata(metadata) {
    if (!metadata || typeof metadata !== "object") {
        return {};
    }

    const blocked = new Set([
        "password",
        "sifre",
        "code",
        "otp",
        "token",
        "sessionToken",
        "secret",
        "secret_enc",
        "qrCodeDataUrl",
    ]);

    return Object.fromEntries(
        Object.entries(metadata)
            .filter(([key]) => !blocked.has(key))
            .slice(0, 30)
    );
}

async function writeSecurityEvent({
    req,
    userKey = null,
    eventType,
    success = true,
    metadata = {},
}) {
    if (!eventType) return;

    const row = {
        user_key:
            userKey === null ||
            userKey === undefined
                ? null
                : String(userKey),

        event_type: String(eventType).slice(0, 100),

        success: Boolean(success),

        ip_address: req
            ? clientIp(req)
            : null,

        user_agent: req
            ? String(
                req.headers["user-agent"] || ""
              ).slice(0, 500)
            : null,

        metadata:
            sanitizeMetadata(metadata),

        created_at:
            new Date().toISOString(),
    };

    try {
        await request("security_events", {
            method: "POST",
            headers: {
                Prefer: "return=minimal",
            },
            body: JSON.stringify(row),
        });
    } catch (error) {
        /*
         * Audit servisindeki gecici hata
         * login sistemini devre disi birakmasin.
         */
        console.error(
            "[SECURITY AUDIT]",
            error?.message || "Audit error"
        );
    }
}

module.exports = {
    writeSecurityEvent,
    clientIp,
};
