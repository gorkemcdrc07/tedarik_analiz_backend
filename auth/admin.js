const { request } = require("./supabase");

function normalizeRole(value) {
    return String(value || "")
        .trim()
        .toLowerCase();
}

async function requireAdmin(req, res, next) {
    try {
        const userKey = req.auth?.userKey;

        if (!userKey) {
            return res.status(401).json({
                error: "Oturum bulunamadi.",
            });
        }

        const id = encodeURIComponent(
            String(userKey)
        );

        const rows = await request(
            `Login?id=eq.${id}` +
            `&select=id,kullanici_adi,kullanici,rol`
        );

        if (!Array.isArray(rows) || !rows.length) {
            return res.status(401).json({
                error: "Kullanici bulunamadi.",
            });
        }

        const user = rows[0];

        if (normalizeRole(user.rol) !== "admin") {
            return res.status(403).json({
                error: "Bu islem icin admin yetkisi gerekiyor.",
            });
        }

        req.authUser = user;

        return next();
    } catch (error) {
        console.error(
            "[ADMIN AUTH]",
            error?.message ||
                "Admin authorization error"
        );

        return res.status(500).json({
            error: "Admin yetkisi kontrol edilemedi.",
        });
    }
}

module.exports = {
    requireAdmin,
};