const express = require("express");
const { request } = require("./supabase");
const { requireAuth } = require("./middleware");
const { requirePermission } = require("./permissions");

const router = express.Router();

/*
 * Internal application data API.
 *
 * Browser -> authenticated backend -> Supabase service role
 *
 * Supabase service-role credentials are never returned to the browser.
 */

router.use(requireAuth);

const PARSIYEL_SIPARIS_SCREEN = "/SiparisIslemleri/ParsiyelSiparisOlustur";
const PROJE_SCREEN = "/Tanimlamalar/ProjeEkle";
function normalizeProjeTanitimKartiPayload(body) {
    const source =
        body && typeof body === "object"
            ? body
            : {};

    const ID = String(source.ID ?? "").trim();
    const FirmaUnvani = String(source.FirmaUnvani ?? "").trim();
    const ProjeAdi = String(source.ProjeAdi ?? "").trim();

    if (!/^[1-9][0-9]*$/.test(ID)) {
        return {
            error: "Geçerli bir proje ID zorunludur.",
        };
    }

    if (!FirmaUnvani) {
        return {
            error: "Firma unvanı zorunludur.",
        };
    }

    if (!ProjeAdi) {
        return {
            error: "Proje adı zorunludur.",
        };
    }

    if (ID.length > 50) {
        return {
            error: "Proje ID çok uzun.",
        };
    }

    if (FirmaUnvani.length > 500) {
        return {
            error: "Firma unvanı çok uzun.",
        };
    }

    if (ProjeAdi.length > 500) {
        return {
            error: "Proje adı çok uzun.",
        };
    }

    return {
        data: {
            ID,
            FirmaUnvani,
            ProjeAdi,
        },
    };
}

// GET /api/data/firmalar
router.get("/firmalar", async (req, res) => {
    try {
        const data = await request(
            "Firmalar?select=firma_adi,firma_id"
        );

        res.set("Cache-Control", "no-store");

        return res.json({
            ok: true,
            data: Array.isArray(data) ? data : [],
        });
    } catch (error) {
        console.error("Firmalar read error:", error.message);

        return res.status(500).json({
            ok: false,
            error: "Firmalar alınamadı.",
        });
    }
});

// GET /api/data/hesap-adlari
router.get("/hesap-adlari", async (req, res) => {
    try {
        const data = await request(
            "Fiyat_Ekleme_Hesap_Adlari?select=tip_id,detay_id,hizmet_adi,kdv_oran"
        );

        res.set("Cache-Control", "no-store");

        return res.json({
            ok: true,
            data: Array.isArray(data) ? data : [],
        });
    } catch (error) {
        console.error("Hesap adlari read error:", error.message);

        return res.status(500).json({
            ok: false,
            error: "Hesap adları alınamadı.",
        });
    }
});

// GET /api/data/projeler/options
// Siparis ekranlari yalnizca minimum proje bilgisini alir.
router.get("/projeler/options", async (req, res) => {
    try {
        const data = await request(
            "Projeler?select=id,Proje_Adi&order=Proje_Adi.asc"
        );

        res.set("Cache-Control", "no-store");

        return res.json({
            ok: true,
            data: Array.isArray(data) ? data : [],
        });
    } catch (error) {
        console.error(
            "Proje options read error:",
            error.message
        );

        return res.status(500).json({
            ok: false,
            error: "Projeler alınamadı.",
        });
    }
});

// GET /api/data/projeler
// Tam proje verisi sadece proje yonetim yetkisiyle okunabilir.
router.get(
    "/projeler",
    requirePermission(
        PROJE_SCREEN,
        "Görüntüle"
    ),
    async (req, res) => {
        try {
            const data = await request(
                "Projeler?select=*&order=id.desc"
            );

            res.set("Cache-Control", "no-store");

            return res.json({
                ok: true,
                data: Array.isArray(data) ? data : [],
            });
        } catch (error) {
            console.error(
                "Projeler read error:",
                error.message
            );

            return res.status(500).json({
                ok: false,
                error: "Projeler alınamadı.",
            });
        }
    }
);

// POST /api/data/proje-tanitim-karti
router.post(
    "/proje-tanitim-karti",
    requirePermission(
        PARSIYEL_SIPARIS_SCREEN,
        "Kaydet"
    ),
    async (req, res) => {
        try {
            const normalized =
                normalizeProjeTanitimKartiPayload(req.body);

            if (normalized.error) {
                return res.status(400).json({
                    ok: false,
                    error: normalized.error,
                });
            }

            const payload = normalized.data;
            const encodedId =
                encodeURIComponent(payload.ID);

            const existing = await request(
                `Proje_Tanitim_Karti?ID=eq.${encodedId}` +
                "&select=ID,FirmaUnvani,ProjeAdi&limit=1"
            );

            if (
                Array.isArray(existing) &&
                existing.length > 0
            ) {
                return res.status(409).json({
                    ok: false,
                    error: "Bu ID zaten kayıtlı.",
                    data: existing[0],
                });
            }

            const created = await request(
                "Proje_Tanitim_Karti",
                {
                    method: "POST",
                    headers: {
                        Prefer: "return=representation",
                    },
                    body: JSON.stringify(payload),
                }
            );

            const row =
                Array.isArray(created)
                    ? created[0] || null
                    : created || null;

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.status(201).json({
                ok: true,
                data: row,
            });
        } catch (error) {
            console.error(
                "Proje tanitim karti create error:",
                error.message
            );

            return res.status(500).json({
                ok: false,
                error: "Proje tanıtım kartı eklenemedi.",
            });
        }
    }
);
// GET /api/data/proje-tanitim-karti
router.get("/proje-tanitim-karti", async (req, res) => {
    try {
        const data = await request(
            "Proje_Tanitim_Karti?select=ID,FirmaUnvani,ProjeAdi&order=FirmaUnvani.asc,ProjeAdi.asc"
        );

        res.set("Cache-Control", "no-store");

        return res.json({
            ok: true,
            data: Array.isArray(data) ? data : [],
        });
    } catch (error) {
        console.error(
            "Proje tanitim karti read error:",
            error.message
        );

        return res.status(500).json({
            ok: false,
            error: "Proje tanıtım kartları alınamadı.",
        });
    }
});




function normalizeProjectPayload(body) {
    const source =
        body && typeof body === "object"
            ? body
            : {};

    const text = (value, maxLength = 500) => {
        if (value === null || value === undefined) {
            return "";
        }

        return String(value)
            .trim()
            .slice(0, maxLength);
    };

    const nullable = (value, maxLength = 500) => {
        const normalized = text(
            value,
            maxLength
        );

        return normalized || null;
    };

    return {
        Proje_Adi: text(source.Proje_Adi, 250),
        vkn: text(source.vkn, 20),
        proje_id: text(source.proje_id, 100),

        Musteri_Siparis_No:
            nullable(
                source.Musteri_Siparis_No,
                250
            ),

        Yukleme_Firma_Adres_Adi:
            nullable(
                source.Yukleme_Firma_Adres_Adi,
                500
            ),

        Alici_Firma_Cari_Unvani:
            nullable(
                source.Alici_Firma_Cari_Unvani,
                500
            ),

        Urun:
            nullable(source.Urun, 500),

        Kap_Adet:
            nullable(source.Kap_Adet, 100),

        Ambalaj_Tipi:
            nullable(
                source.Ambalaj_Tipi,
                100
            ),

        Brut_KG:
            nullable(source.Brut_KG, 100),
    };
}

function validateProjectPayload(payload) {
    if (!payload.Proje_Adi) {
        return "Proje adi zorunludur.";
    }

    if (!payload.vkn) {
        return "VKN zorunludur.";
    }

    if (!payload.proje_id) {
        return "Proje ID zorunludur.";
    }

    if (!/^\d+$/.test(payload.vkn)) {
        return "VKN yalnizca rakamlardan olusmalidir.";
    }

    return null;
}

function normalizeProjectId(value) {
    const id =
        String(value ?? "").trim();

    if (!/^\d+$/.test(id)) {
        return null;
    }

    return id;
}

// POST /api/data/projeler
router.post(
    "/projeler",
    requirePermission(PROJE_SCREEN, "Ekle"),
    async (req, res) => {
        try {
            const payload =
                normalizeProjectPayload(req.body);

            const validationError =
                validateProjectPayload(payload);

            if (validationError) {
                return res.status(400).json({
                    ok: false,
                    error: validationError,
                });
            }

            const data = await request(
                "Projeler",
                {
                    method: "POST",
                    headers: {
                        Prefer:
                            "return=representation",
                    },
                    body:
                        JSON.stringify([payload]),
                }
            );

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.status(201).json({
                ok: true,
                data:
                    Array.isArray(data) &&
                    data.length
                        ? data[0]
                        : null,
            });
        } catch (error) {
            console.error(
                "Proje create error:",
                error?.message
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Proje eklenemedi.",
            });
        }
    }
);

// PATCH /api/data/projeler/:id
router.patch(
    "/projeler/:id",
    requirePermission(
        PROJE_SCREEN,
        "Güncelle"
    ),
    async (req, res) => {
        try {
            const id =
                normalizeProjectId(
                    req.params.id
                );

            if (!id) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Gecersiz proje ID.",
                });
            }

            const payload =
                normalizeProjectPayload(req.body);

            const validationError =
                validateProjectPayload(payload);

            if (validationError) {
                return res.status(400).json({
                    ok: false,
                    error: validationError,
                });
            }

            const data = await request(
                `Projeler?id=eq.${encodeURIComponent(id)}`,
                {
                    method: "PATCH",
                    headers: {
                        Prefer:
                            "return=representation",
                    },
                    body:
                        JSON.stringify(payload),
                }
            );

            if (
                !Array.isArray(data) ||
                !data.length
            ) {
                return res.status(404).json({
                    ok: false,
                    error:
                        "Proje bulunamadi.",
                });
            }

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json({
                ok: true,
                data: data[0],
            });
        } catch (error) {
            console.error(
                "Proje update error:",
                error?.message
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Proje guncellenemedi.",
            });
        }
    }
);

// DELETE /api/data/projeler/:id
router.delete(
    "/projeler/:id",
    requirePermission(
        PROJE_SCREEN,
        "Sil"
    ),
    async (req, res) => {
        try {
            const id =
                normalizeProjectId(
                    req.params.id
                );

            if (!id) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Gecersiz proje ID.",
                });
            }

            const data = await request(
                `Projeler?id=eq.${encodeURIComponent(id)}`,
                {
                    method: "DELETE",
                    headers: {
                        Prefer:
                            "return=representation",
                    },
                }
            );

            if (
                !Array.isArray(data) ||
                !data.length
            ) {
                return res.status(404).json({
                    ok: false,
                    error:
                        "Proje bulunamadi.",
                });
            }

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json({
                ok: true,
            });
        } catch (error) {
            console.error(
                "Proje delete error:",
                error?.message
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Proje silinemedi.",
            });
        }
    }
);
module.exports = router;