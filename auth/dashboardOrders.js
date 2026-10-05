const express = require("express");
const { requireAuth } = require("./middleware");
const { request } = require("./supabase");

const router = express.Router();

const TABLE = "siparis_aktarim_loglari";

function cleanProjectName(value) {
    return String(value || "")
        .trim()
        .slice(0, 200);
}

function parseOrderCount(value) {
    const count = Number(value);

    if (
        !Number.isInteger(count) ||
        count < 1 ||
        count > 100000
    ) {
        return null;
    }

    return count;
}

router.post(
    "/order-exports",
    requireAuth,
    async (req, res) => {
        try {
            const projeAdi =
                cleanProjectName(
                    req.body?.projeAdi
                );

            const siparisAdedi =
                parseOrderCount(
                    req.body?.siparisAdedi
                );

            if (!projeAdi) {
                return res.status(400).json({
                    ok: false,
                    error: "Proje adi zorunludur.",
                });
            }

            if (siparisAdedi === null) {
                return res.status(400).json({
                    ok: false,
                    error: "Siparis adedi gecersiz.",
                });
            }

            const userKey =
                String(
                    req.auth?.userKey || ""
                ).trim();

            if (!userKey) {
                return res.status(401).json({
                    ok: false,
                    error: "Kullanici oturumu bulunamadi.",
                });
            }

            const createdAt =
                new Date().toISOString();

            await request(TABLE, {
                method: "POST",
                headers: {
                    Prefer: "return=minimal",
                },
                body: JSON.stringify({
                    proje_adi: projeAdi,
                    siparis_adedi: siparisAdedi,
                    user_key: userKey,
                    created_at: createdAt,
                }),
            });

            return res.status(201).json({
                ok: true,
                projeAdi,
                siparisAdedi,
                createdAt,
            });
        } catch (error) {
            console.error(
                "[DASHBOARD ORDER EXPORT POST]",
                error?.message || error
            );

            return res.status(500).json({
                ok: false,
                error: "Siparis aktarim kaydi olusturulamadi.",
            });
        }
    }
);

router.get(
    "/order-exports",
    requireAuth,
    async (req, res) => {
        try {
            const limitValue =
                Number(req.query?.limit);

            const limit =
                Number.isInteger(limitValue) &&
                limitValue > 0
                    ? Math.min(limitValue, 1000)
                    : 500;

            const rows =
                await request(
                    `${TABLE}?select=id,proje_adi,siparis_adedi,user_key,created_at&order=created_at.desc&limit=${limit}`,
                    {
                        method: "GET",
                    }
                );

            return res.json({
                ok: true,
                data:
                    Array.isArray(rows)
                        ? rows
                        : [],
            });
        } catch (error) {
            console.error(
                "[DASHBOARD ORDER EXPORT GET]",
                error?.message || error
            );

            return res.status(500).json({
                ok: false,
                error: "Siparis aktarim kayitlari alinamadi.",
            });
        }
    }
);

module.exports = router;
