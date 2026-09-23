const express = require("express");
const bcrypt = require("bcryptjs");
const { rateLimit } = require("express-rate-limit");

const { request } = require("./supabase");
const { requireAuth } = require("./middleware");
const { requireAdmin } = require("./admin");
const { writeSecurityEvent } = require("./audit");
const { encryptReelSecret } = require("./reelCrypto");

const router = express.Router();

const BCRYPT_ROUNDS = 12;
const adminApiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 120,
    standardHeaders: "draft-7",
    legacyHeaders: false,

    handler: (req, res) => {
        return res.status(429).json({
            error:
                "Cok fazla yonetim istegi. Lutfen daha sonra tekrar deneyin.",
        });
    },
});

const ALLOWED_ROLES =
    new Set(["admin", "kullanici"]);

function normalizeText(value, max = 250) {
    return String(value ?? "")
        .trim()
        .slice(0, max);
}

function normalizeUsername(value) {
    return normalizeText(value, 250)
        .toLowerCase();
}

function normalizeRole(value) {
    const role =
        normalizeText(value, 50)
            .toLowerCase();

    if (!ALLOWED_ROLES.has(role)) {
        throw new Error("Gecersiz rol.");
    }

    return role;
}

function normalizeArray(value) {
    let parsed = value;

    if (typeof value === "string") {
        try {
            parsed = JSON.parse(value);
        } catch {
            parsed = value
                .split(",")
                .map(item => item.trim())
                .filter(Boolean);
        }
    }

    if (!Array.isArray(parsed)) {
        return [];
    }

    return [
        ...new Set(
            parsed
                .map(item =>
                    normalizeText(item, 250)
                )
                .filter(Boolean)
        ),
    ].slice(0, 500);
}

function serializeArray(value) {
    return JSON.stringify(
        normalizeArray(value)
    );
}

function safeUser(row) {
    return {
        id:
            row.id,

        kullanici_adi:
            row.kullanici_adi || "",

        kullanici:
            row.kullanici || "",

        rol:
            row.rol || "kullanici",

        Reel_kullanici:
            row.Reel_kullanici || "",

        /*
         * Reel_sifre istemciye ASLA donmez.
         * Sadece credential var/yok bilgisi.
         */
        hasReelCredential:
            Boolean(row.Reel_sifre),

        allowedScreens:
            normalizeArray(
                row.allowedScreens
            ),

        allowedButtons:
            normalizeArray(
                row.allowedButtons
            ),
    };
}

function validatePassword(password) {
    const value =
        String(password ?? "");

    if (value.length < 10) {
        throw new Error(
            "Sifre en az 10 karakter olmali."
        );
    }

    if (value.length > 200) {
        throw new Error(
            "Sifre cok uzun."
        );
    }

    return value;
}

async function getAdminCount() {
    const rows = await request(
        "Login?rol=eq.admin&select=id"
    );

    return Array.isArray(rows)
        ? rows.length
        : 0;
}

async function getUserById(id) {
    const rows = await request(
        `Login?id=eq.${encodeURIComponent(id)}` +
        `&select=id,kullanici_adi,kullanici,rol&limit=1`
    );

    return Array.isArray(rows) && rows.length
        ? rows[0]
        : null;
}

async function usernameExists(
    username,
    excludeId = null
) {
    const encoded =
        encodeURIComponent(username);

    let path =
        `Login?kullanici_adi=eq.${encoded}` +
        `&select=id&limit=2`;

    const rows =
        await request(path);

    if (!Array.isArray(rows)) {
        return false;
    }

    return rows.some(
        row =>
            String(row.id) !==
            String(excludeId ?? "")
    );
}


/*
 * Tüm admin user endpointleri:
 * 1. geçerli HttpOnly session
 * 2. DB'den güncel admin rolü
 */
router.use(adminApiLimiter);
router.use(requireAuth);
router.use(requireAdmin);


/*
 * GET /api/admin/users
 *
 * sifre / password_hash / Reel_sifre dönmez.
 */
router.get("/", async (req, res) => {
    try {
        const rows =
            await request(
                "Login" +
                "?select=" +
                [
                    "id",
                    "kullanici_adi",
                    "kullanici",
                    "rol",
                    "Reel_kullanici",
                    "Reel_sifre",
                    "allowedScreens",
                    "allowedButtons",
                ].join(",") +
                "&order=id.asc"
            );

        return res.json({
            ok: true,
            users: Array.isArray(rows)
                ? rows.map(safeUser)
                : [],
        });
    } catch (error) {
        console.error(
            "[ADMIN USERS LIST]",
            error?.message
        );

        return res.status(500).json({
            error:
                "Kullanici listesi alinamadi.",
        });
    }
});


/*
 * POST /api/admin/users
 */
router.post("/", async (req, res) => {
    try {
        const username =
            normalizeUsername(
                req.body?.kullanici_adi
            );

        const displayName =
            normalizeText(
                req.body?.kullanici,
                250
            );

        if (!username || !displayName) {
            return res.status(400).json({
                error:
                    "Kullanici maili ve kullanici adi zorunludur.",
            });
        }

        if (
            await usernameExists(username)
        ) {
            return res.status(409).json({
                error:
                    "Bu kullanici maili zaten kayitli.",
            });
        }

        const password =
            validatePassword(
                req.body?.password
            );

        const role =
            normalizeRole(
                req.body?.rol ||
                "kullanici"
            );

        const passwordHash =
            await bcrypt.hash(
                password,
                BCRYPT_ROUNDS
            );

        const reelUser =
            normalizeText(
                req.body?.Reel_kullanici,
                250
            ) || null;

        /*
         * Reel/TMS sifresi tarayici tarafindan
         * yalnizca yonetici tarafindan girilir.
         * Veritabanina AES-256-GCM ile sifrelenerek yazilir.
         */
        const reelPassword =
            req.body?.Reel_sifre
                ? encryptReelSecret(
                    String(
                        req.body.Reel_sifre
                    ).slice(0, 500)
                )
                : null;

        const payload = {
            kullanici_adi:
                username,

            kullanici:
                displayName,

            rol:
                role,

            /*
             * Yeni kullanicilarda plaintext
             * uygulama sifresi DB'ye yazilmaz.
             */
            sifre:
                null,

            password_hash:
                passwordHash,

            Reel_kullanici:
                reelUser,

            Reel_sifre:
                reelPassword,

            allowedScreens:
                serializeArray(
                    req.body?.allowedScreens
                ),

            allowedButtons:
                serializeArray(
                    req.body?.allowedButtons
                ),
        };

        const created =
            await request(
                "Login",
                {
                    method: "POST",

                    headers: {
                        Prefer:
                            "return=representation",
                    },

                    body:
                        JSON.stringify(
                            payload
                        ),
                }
            );

        const row =
            Array.isArray(created)
                ? created[0]
                : null;

        if (!row) {
            throw new Error(
                "Insert response missing."
            );
        }

        await writeSecurityEvent({
            req,
            userKey:
                req.auth.userKey,

            eventType:
                "ADMIN_USER_CREATED",

            success:
                true,

            metadata: {
                targetUserId:
                    row.id,

                targetUsername:
                    username,

                role,
            },
        });

        return res.status(201).json({
            ok: true,
            user:
                safeUser(row),
        });
    } catch (error) {
        console.error(
            "[ADMIN USER CREATE]",
            error?.message
        );

        const message =
            String(
                error?.message || ""
            );

        if (
            message.includes(
                "Sifre en az"
            ) ||
            message.includes(
                "Sifre cok"
            ) ||
            message.includes(
                "Gecersiz rol"
            )
        ) {
            return res.status(400).json({
                error: message,
            });
        }

        return res.status(500).json({
            error:
                "Kullanici olusturulamadi.",
        });
    }
});


/*
 * PATCH /api/admin/users/:id
 *
 * Uygulama sifresi bu endpoint ile
 * degistirilemez.
 */
router.patch("/:id", async (req, res) => {
    try {
        const id =
            normalizeText(
                req.params.id,
                50
            );

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                error:
                    "Gecersiz kullanici ID.",
            });
        }

        const username =
            normalizeUsername(
                req.body?.kullanici_adi
            );

        const displayName =
            normalizeText(
                req.body?.kullanici,
                250
            );

        if (!username || !displayName) {
            return res.status(400).json({
                error:
                    "Kullanici maili ve kullanici adi zorunludur.",
            });
        }

        if (
            await usernameExists(
                username,
                id
            )
        ) {
            return res.status(409).json({
                error:
                    "Bu kullanici maili zaten kayitli.",
            });
        }

        const role =
            normalizeRole(
                req.body?.rol ||
                "kullanici"
            );

        const existingUser =
            await getUserById(id);

        if (!existingUser) {
            return res.status(404).json({
                error:
                    "Kullanici bulunamadi.",
            });
        }

        const existingRole =
            normalizeText(
                existingUser.rol,
                50
            ).toLowerCase();

        /*
         * Aktif admin kendi admin rolunu kaldiramaz.
         */
        if (
            String(req.auth.userKey) === String(id) &&
            existingRole === "admin" &&
            role !== "admin"
        ) {
            return res.status(400).json({
                error:
                    "Aktif admin kendi admin rolunu kaldiramaz.",
            });
        }

        /*
         * Son admin hesabi de-admin yapilamaz.
         */
        if (
            existingRole === "admin" &&
            role !== "admin"
        ) {
            const adminCount =
                await getAdminCount();

            if (adminCount <= 1) {
                return res.status(400).json({
                    error:
                        "Sistemdeki son admin hesabi kaldirilamaz.",
                });
            }
        }
        const payload = {
            kullanici_adi:
                username,

            kullanici:
                displayName,

            rol:
                role,

            Reel_kullanici:
                normalizeText(
                    req.body?.Reel_kullanici,
                    250
                ) || null,

            allowedScreens:
                serializeArray(
                    req.body?.allowedScreens
                ),

            allowedButtons:
                serializeArray(
                    req.body?.allowedButtons
                ),
        };

        /*
         * Reel sifre ancak yeni bir deger
         * acikca gonderilirse degisir.
         *
         * Bos alan mevcut credential'i silmez.
         */
        if (
            typeof req.body?.Reel_sifre ===
                "string" &&
            req.body.Reel_sifre.length > 0
        ) {
            payload.Reel_sifre =
                encryptReelSecret(
                    req.body.Reel_sifre
                        .slice(0, 500)
                );
        }

        const updated =
            await request(
                `Login?id=eq.${encodeURIComponent(id)}`,
                {
                    method: "PATCH",

                    headers: {
                        Prefer:
                            "return=representation",
                    },

                    body:
                        JSON.stringify(
                            payload
                        ),
                }
            );

        const row =
            Array.isArray(updated)
                ? updated[0]
                : null;

        if (!row) {
            return res.status(404).json({
                error:
                    "Kullanici bulunamadi.",
            });
        }

        await writeSecurityEvent({
            req,
            userKey:
                req.auth.userKey,

            eventType:
                "ADMIN_USER_UPDATED",

            success:
                true,

            metadata: {
                targetUserId:
                    id,

                targetUsername:
                    username,

                role,
            },
        });

        return res.json({
            ok: true,
            user:
                safeUser(row),
        });
    } catch (error) {
        console.error(
            "[ADMIN USER UPDATE]",
            error?.message
        );

        if (
            String(
                error?.message || ""
            ).includes("Gecersiz rol")
        ) {
            return res.status(400).json({
                error:
                    "Gecersiz rol.",
            });
        }

        return res.status(500).json({
            error:
                "Kullanici guncellenemedi.",
        });
    }
});


/*
 * PUT /api/admin/users/:id/password
 */
router.put(
    "/:id/password",
    async (req, res) => {
        try {
            const id =
                normalizeText(
                    req.params.id,
                    50
                );

            if (!/^\d+$/.test(id)) {
                return res.status(400).json({
                    error:
                        "Gecersiz kullanici ID.",
                });
            }

            const password =
                validatePassword(
                    req.body?.password
                );

            const hash =
                await bcrypt.hash(
                    password,
                    BCRYPT_ROUNDS
                );

            const updated =
                await request(
                    `Login?id=eq.${encodeURIComponent(id)}`,
                    {
                        method: "PATCH",

                        headers: {
                            Prefer:
                                "return=representation",
                        },

                        body:
                            JSON.stringify({
                                password_hash:
                                    hash,

                                /*
                                 * Eski plaintext uygulama
                                 * sifresini ayni anda temizle.
                                 */
                                sifre:
                                    null,
                            }),
                    }
                );

            const row =
                Array.isArray(updated)
                    ? updated[0]
                    : null;

            if (!row) {
                return res.status(404).json({
                    error:
                        "Kullanici bulunamadi.",
                });
            }

            /*
             * Hedef kullanicinin tum mevcut
             * sessionlarini iptal et.
             */
            await request(
                `login_sessions` +
                `?user_key=eq.${encodeURIComponent(id)}` +
                `&revoked_at=is.null`,
                {
                    method: "PATCH",

                    headers: {
                        Prefer:
                            "return=minimal",
                    },

                    body:
                        JSON.stringify({
                            revoked_at:
                                new Date()
                                    .toISOString(),

                            revoke_reason:
                                "password_changed",
                        }),
                }
            );

            await writeSecurityEvent({
                req,

                userKey:
                    req.auth.userKey,

                eventType:
                    "ADMIN_PASSWORD_CHANGED",

                success:
                    true,

                metadata: {
                    targetUserId:
                        id,
                },
            });

            return res.json({
                ok: true,
            });
        } catch (error) {
            console.error(
                "[ADMIN PASSWORD]",
                error?.message
            );

            const message =
                String(
                    error?.message || ""
                );

            if (
                message.includes(
                    "Sifre en az"
                ) ||
                message.includes(
                    "Sifre cok"
                )
            ) {
                return res.status(400).json({
                    error: message,
                });
            }

            return res.status(500).json({
                error:
                    "Sifre degistirilemedi.",
            });
        }
    }
);


/*
 * DELETE /api/admin/users/:id
 *
 * Kendini silmeyi engelliyoruz.
 */
router.delete("/:id", async (req, res) => {
    try {
        const id =
            normalizeText(
                req.params.id,
                50
            );

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                error:
                    "Gecersiz kullanici ID.",
            });
        }

        if (
            String(req.auth.userKey) ===
            String(id)
        ) {
            return res.status(400).json({
                error:
                    "Aktif oturumdaki kullanici kendisini silemez.",
            });
        }

        const targetUser =
            await getUserById(id);

        if (!targetUser) {
            return res.status(404).json({
                error:
                    "Kullanici bulunamadi.",
            });
        }

        /*
         * Son admin hesabi silinemez.
         */
        if (
            normalizeText(
                targetUser.rol,
                50
            ).toLowerCase() === "admin"
        ) {
            const adminCount =
                await getAdminCount();

            if (adminCount <= 1) {
                return res.status(400).json({
                    error:
                        "Sistemdeki son admin hesabi silinemez.",
                });
            }
        }
        /*
         * Once hedef kullanicinin sessionlarini
         * revoke et.
         */
        await request(
            `login_sessions` +
            `?user_key=eq.${encodeURIComponent(id)}` +
            `&revoked_at=is.null`,
            {
                method: "PATCH",

                headers: {
                    Prefer:
                        "return=minimal",
                },

                body:
                    JSON.stringify({
                        revoked_at:
                            new Date()
                                .toISOString(),

                        revoke_reason:
                            "user_deleted",
                    }),
            }
        );

        const deleted =
            await request(
                `Login?id=eq.${encodeURIComponent(id)}`,
                {
                    method: "DELETE",

                    headers: {
                        Prefer:
                            "return=representation",
                    },
                }
            );

        const row =
            Array.isArray(deleted)
                ? deleted[0]
                : null;

        if (!row) {
            return res.status(404).json({
                error:
                    "Kullanici bulunamadi.",
            });
        }

        await writeSecurityEvent({
            req,

            userKey:
                req.auth.userKey,

            eventType:
                "ADMIN_USER_DELETED",

            success:
                true,

            metadata: {
                targetUserId:
                    id,

                targetUsername:
                    row.kullanici_adi ||
                    null,
            },
        });

        return res.json({
            ok: true,
        });
    } catch (error) {
        console.error(
            "[ADMIN USER DELETE]",
            error?.message
        );

        return res.status(500).json({
            error:
                "Kullanici silinemedi.",
        });
    }
});

module.exports = router;