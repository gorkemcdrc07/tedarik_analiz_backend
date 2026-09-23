const { request } = require("./supabase");

function normalizeRole(value) {
    return String(value || "")
        .trim()
        .toLowerCase();
}

function parseArray(value) {
    if (Array.isArray(value)) {
        return value
            .map((item) => String(item || "").trim())
            .filter(Boolean);
    }

    if (typeof value !== "string") {
        return [];
    }

    const trimmed = value.trim();

    if (!trimmed) {
        return [];
    }

    try {
        const parsed = JSON.parse(trimmed);

        if (Array.isArray(parsed)) {
            return parsed
                .map((item) => String(item || "").trim())
                .filter(Boolean);
        }
    } catch {
        // Legacy comma-separated values are handled below.
    }

    return trimmed
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
}

async function getCurrentUserPermissions(userKey) {
    const id = encodeURIComponent(
        String(userKey)
    );

    const rows = await request(
        `Login?id=eq.${id}` +
        `&select=id,kullanici_adi,kullanici,rol,allowedScreens,allowedButtons`
    );

    if (!Array.isArray(rows) || !rows.length) {
        return null;
    }

    const row = rows[0];

    return {
        ...row,
        allowedScreens: parseArray(
            row.allowedScreens
        ),
        allowedButtons: parseArray(
            row.allowedButtons
        ),
    };
}

function requirePermission(
    screen,
    button = null
) {
    const requiredScreen =
        String(screen || "").trim();

    const requiredButton =
        button === null
            ? null
            : String(button || "").trim();

    if (!requiredScreen) {
        throw new Error(
            "Permission screen is required."
        );
    }

    return async function permissionMiddleware(
        req,
        res,
        next
    ) {
        try {
            const userKey =
                req.auth?.userKey;

            if (!userKey) {
                return res.status(401).json({
                    error: "Oturum bulunamadi.",
                });
            }

            const user =
                await getCurrentUserPermissions(
                    userKey
                );

            if (!user) {
                return res.status(401).json({
                    error: "Kullanici bulunamadi.",
                });
            }

            /*
             * Admin mevcut frontend davranisiyla
             * uyumlu olarak tum ekran ve buton
             * yetkilerini otomatik gecer.
             */
            if (
                normalizeRole(user.rol) ===
                "admin"
            ) {
                req.authUser = user;
                return next();
            }

            if (
                !user.allowedScreens.includes(
                    requiredScreen
                )
            ) {
                return res.status(403).json({
                    error:
                        "Bu ekran icin yetkiniz bulunmuyor.",
                });
            }

            if (
                requiredButton &&
                !user.allowedButtons.includes(
                    requiredButton
                )
            ) {
                return res.status(403).json({
                    error:
                        "Bu islem icin yetkiniz bulunmuyor.",
                });
            }

            req.authUser = user;

            return next();
        } catch (error) {
            console.error(
                "[PERMISSION AUTH]",
                error?.message ||
                    "Permission authorization error"
            );

            return res.status(500).json({
                error:
                    "Yetki kontrolu yapilamadi.",
            });
        }
    };
}

module.exports = {
    requirePermission,
};