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
const TESLIM_NOKTALARI_SCREEN = "/SiparisIslemleri/TeslimNoktalari";
const SIPARIS_OLUSTUR_SCREEN = "/SiparisIslemleri/SiparisOlustur";
const FIYATLANDIRMA_SCREEN = "/fiyatlandirma/seferFiyatlandirma";
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

// ============================================================
// BUNGE_FIYAT_API_V1
// Sefer fiyatlandirma fiyatlarini browser yerine backend okur.
// ============================================================
router.post(
    "/fiyatlandirma/bunge-fiyatlar",
    requirePermission(
        FIYATLANDIRMA_SCREEN,
        "Hesapla"
    ),
    async (req, res) => {
        try {
            const sourceCities =
                Array.isArray(req.body?.cities)
                    ? req.body.cities
                    : [];

            const cities = [
                ...new Set(
                    sourceCities
                        .map((value) =>
                            String(value ?? "").trim()
                        )
                        .filter(Boolean)
                ),
            ];

            if (
                cities.length < 1 ||
                cities.length > 200
            ) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "1 ile 200 arasında teslim ili gerekli.",
                });
            }

            if (
                cities.some(
                    (value) => value.length > 100
                )
            ) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Teslim ili değeri çok uzun.",
                });
            }

            const encodedCities = cities
                .map((value) =>
                    `"${String(value)
                        .replace(/\\/g, "\\\\")
                        .replace(/"/g, '\\"')}"`
                )
                .join(",");

            const query =
                "bungeFiyatlar" +
                "?select=teslim_il,teslim_ilce,mesafe,tir,kamyon" +
                "&teslim_il=in.(" +
                encodeURIComponent(encodedCities) +
                ")";

            const data = await request(query);

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json({
                ok: true,
                data: Array.isArray(data)
                    ? data
                    : [],
            });
        } catch (error) {
            console.error(
                "Bunge fiyat read error:",
                error.message
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Bunge fiyatları alınamadı.",
            });
        }
    }
);
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


// ============================================================
function normalizeBallogName(value) {
    return String(value ?? "")
        .replace(/\s+/g, " ")
        .trim()
        .toLocaleLowerCase("tr-TR")
        .replace(/\u0131/g, "i");
}

// SIPARIS_OLUSTUR_BALLOG_V1
// BALLOG teslim noktalarini tarayici yerine backend uzerinden yonetir.
// ============================================================

router.get(
    "/siparis-olustur/ballog-teslim-noktalari",
    requirePermission(
        SIPARIS_OLUSTUR_SCREEN,
        "Görüntüle"
    ),
    async (req, res) => {
        try {
            const cariHesapId = "63625";

            const query =
                "ballog_teslim_noktalari" +
                "?select=adres_id,adres_adi,cari_hesap_id" +
                "&cari_hesap_id=eq." +
                encodeURIComponent(cariHesapId) +
                "&order=adres_adi.asc";

            const data = await request(query);

            res.set("Cache-Control", "no-store");

            return res.json({
                ok: true,
                data: Array.isArray(data)
                    ? data
                    : [],
            });
        } catch (error) {
            console.error(
                "[data-api] BALLOG teslim noktalari read:",
                error?.message
            );

            return res.status(500).json({
                ok: false,
                error:
                    "BALLOG teslim noktalari alinamadi.",
            });
        }
    }
);

router.post(
    "/siparis-olustur/ballog-teslim-noktalari/bulk",
    requirePermission(
        SIPARIS_OLUSTUR_SCREEN,
        "Kaydet"
    ),
    async (req, res) => {
        try {
            const rows = Array.isArray(
                req.body?.rows
            )
                ? req.body.rows
                : null;

            if (!rows) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "BALLOG teslim noktasi listesi zorunludur.",
                });
            }

            if (
                rows.length < 1 ||
                rows.length > 5000
            ) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Tek islemde 1-5000 kayit gonderilebilir.",
                });
            }

            const normalized = [];
            const seenIds = new Set();
            const seenNames = new Set();

            for (const source of rows) {
                if (
                    !source ||
                    typeof source !== "object" ||
                    Array.isArray(source)
                ) {
                    return res.status(400).json({
                        ok: false,
                        error:
                            "Gecersiz BALLOG teslim noktasi kaydi.",
                    });
                }

                const adresId = String(
                    source.adres_id ?? ""
                ).trim();

                const adresAdi = String(
                    source.adres_adi ?? ""
                )
                    .replace(/\s+/g, " ")
                    .trim();

                if (!adresId || !adresAdi) {
                    return res.status(400).json({
                        ok: false,
                        error:
                            "adres_id ve adres_adi zorunludur.",
                    });
                }

                if (
                    adresId.length > 250 ||
                    adresAdi.length > 1000
                ) {
                    return res.status(400).json({
                        ok: false,
                        error:
                            "BALLOG teslim noktasi alani cok uzun.",
                    });
                }

                const idKey =
                    adresId.toLocaleUpperCase(
                        "tr-TR"
                    );

                const nameKey =
                    normalizeBallogName(adresAdi);

                if (
                    seenIds.has(idKey) ||
                    seenNames.has(nameKey)
                ) {
                    continue;
                }

                seenIds.add(idKey);
                seenNames.add(nameKey);

                normalized.push({
                    adres_id: adresId,
                    adres_adi: adresAdi,
                    cari_hesap_id: "63625",
                });
            }

            if (!normalized.length) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Eklenecek gecerli BALLOG teslim noktasi yok.",
                });
            }

            const existing = await request(
                "ballog_teslim_noktalari" +
                    "?select=adres_id,adres_adi" +
                    "&cari_hesap_id=eq.63625"
            );

            const existingRows = Array.isArray(existing)
                ? existing
                : [];

            const existingIds = new Set(
                existingRows.map((row) =>
                    String(
                        row?.adres_id ?? ""
                    )
                        .trim()
                        .toLocaleUpperCase(
                            "tr-TR"
                        )
                )
            );

            const existingNames = new Set(
                existingRows.map((row) =>
                    normalizeBallogName(
                        row?.adres_adi
                    )
                )
            );

            const newRows =
                normalized.filter((row) => {
                    const idKey =
                        row.adres_id.toLocaleUpperCase(
                            "tr-TR"
                        );

                const nameKey =
                    normalizeBallogName(row.adres_adi);

                    return (
                        !existingIds.has(idKey) &&
                        !existingNames.has(nameKey)
                    );
                });

            if (!newRows.length) {
                return res.json({
                    ok: true,
                    inserted: 0,
                    skipped: normalized.length,
                    data: [],
                });
            }

            const inserted = [];

            for (
                let i = 0;
                i < newRows.length;
                i += 500
            ) {
                const chunk =
                    newRows.slice(i, i + 500);

                const created = await request(
                    "ballog_teslim_noktalari",
                    {
                        method: "POST",
                        headers: {
                            Prefer:
                                "return=representation",
                        },
                        body:
                            JSON.stringify(chunk),
                    }
                );

                if (Array.isArray(created)) {
                    inserted.push(...created);
                }
            }

            res.set("Cache-Control", "no-store");

            return res.status(201).json({
                ok: true,
                inserted: inserted.length,
                skipped:
                    normalized.length -
                    newRows.length,
                data: inserted,
            });
        } catch (error) {
            console.error(
                "[data-api] BALLOG teslim noktalari bulk:",
                error?.message
            );

            return res.status(500).json({
                ok: false,
                error:
                    "BALLOG teslim noktalari eklenemedi.",
            });
        }
    }
);

// ============================================================
// SIPARIS_OLUSTUR_PROJECT_ROWS_V1
// Siparis Olustur ekrani icin proje bazli dar kapsamli okuma.
// ============================================================

router.get(
    "/siparis-olustur/project-rows",
    requirePermission(
        SIPARIS_OLUSTUR_SCREEN,
        "Görüntüle"
    ),
    async (req, res) => {
        try {
            const projeAdi = String(
                req.query.projeAdi ?? ""
            )
                .replace(/\s+/g, " ")
                .trim();

            if (!projeAdi) {
                return res.status(400).json({
                    error: "Proje adi gerekli.",
                });
            }

            if (projeAdi.length > 500) {
                return res.status(400).json({
                    error: "Proje adi gecersiz.",
                });
            }

            const select = [
                "vkn",
                "proje_id",
                "Musteri_Siparis_No",
                "Alici_Firma_Cari_Unvani",
                "Urun",
                "Kap_Adet",
                "Ambalaj_Tipi",
                "Brut_KG",
                "Yukleme_Firma_Adres_Adi",
                "Proje_Adi",
            ].join(",");

            const query =
                "Projeler?select=" +
                encodeURIComponent(select) +
                "&Proje_Adi=eq." +
                encodeURIComponent(projeAdi) +
                "&order=id.asc";

            const data = await request(query);

            return res.json({
                data: Array.isArray(data) ? data : [],
            });
        } catch (error) {
            console.error(
                "[data-api] siparis-olustur project rows:",
                error
            );

            return res.status(500).json({
                error: "Proje verileri alinamadi.",
            });
        }
    }
);
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

// POST /api/data/siparis-sayaci/next
// Atomik sayaç artışı PostgreSQL RPC tarafından yapılır.
router.post(
    "/siparis-sayaci/next",
    requirePermission(
        PARSIYEL_SIPARIS_SCREEN,
        "Kaydet"
    ),
    async (req, res) => {
        try {
            const customerName = String(
                req.body?.musteriAdi ?? ""
            ).trim();

            const dateValue = Number(
                req.body?.tarih
            );

            if (
                !customerName ||
                customerName.length > 500
            ) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Geçerli bir müşteri adı zorunludur.",
                });
            }

            if (
                !Number.isSafeInteger(dateValue) ||
                dateValue <= 0
            ) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Geçerli bir sayaç tarihi zorunludur.",
                });
            }

            const data = await request(
                "rpc/sonraki_siparis_sayaci",
                {
                    method: "POST",
                    body: JSON.stringify({
                        p_musteri_adi:
                            customerName,
                        p_tarih:
                            dateValue,
                    }),
                }
            );

            const counter = Number(
                Array.isArray(data)
                    ? data[0]
                    : data
            );

            if (
                !Number.isSafeInteger(counter) ||
                counter <= 0
            ) {
                throw new Error(
                    "RPC geçersiz sayaç değeri döndürdü."
                );
            }

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json({
                ok: true,
                data: {
                    counter,
                },
            });
        } catch (error) {
            console.error(
                "Siparis sayaci next error:",
                error?.message
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Sipariş sayacı oluşturulamadı.",
            });
        }
    }
);

// TESLIM_NOKTALARI_API_V1

// SIPARIS_OLUSTUR_TESLIM_NOKTALARI_READ_V1
// Siparis Olustur ekraninin eslestirme ve Excel islemleri icin
// teslim noktalarini kendi ekran yetkisi kapsaminda okur.
router.get(
    "/siparis-olustur/teslim-noktalari",
    requirePermission(
        SIPARIS_OLUSTUR_SCREEN,
        "Görüntüle"
    ),
    async (_req, res) => {
        try {
            const pageSize = 1000;
            const maxRows = 100000;
            const allRows = [];

            for (
                let offset = 0;
                offset < maxRows;
                offset += pageSize
            ) {
                const pagePath =
                    "Teslim_Noktalari" +
                    "?select=*" +
                    "&order=id.asc" +
                    `&offset=${offset}` +
                    `&limit=${pageSize}`;

                const page = await request(
                    pagePath
                );

                const rows = Array.isArray(page)
                    ? page
                    : [];

                allRows.push(...rows);

                if (rows.length < pageSize) {
                    break;
                }

                if (
                    offset + pageSize >=
                    maxRows
                ) {
                    throw new Error(
                        "Siparis Olustur teslim noktalari guvenlik satir limiti asildi."
                    );
                }
            }

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json({
                ok: true,
                data: allRows,
                count: allRows.length,
            });
        } catch (error) {
            console.error(
                "Siparis Olustur teslim noktalari read error:",
                error.message
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Teslim noktaları alınamadı.",
            });
        }
    }
);
// GET /api/data/teslim-noktalari
// Teslim noktalarini guvenli pagination ile listeler.
router.get(
    "/teslim-noktalari",
    requirePermission(
        TESLIM_NOKTALARI_SCREEN,
        "Görüntüle"
    ),
    async (req, res) => {
        try {
            const mode = String(
                req.query.mode ?? "all"
            )
                .trim()
                .toLowerCase();

            if (
                mode !== "all" &&
                mode !== "ids" &&
                mode !== "search"
            ) {
                return res.status(400).json({
                    ok: false,
                    error: "Geçersiz sorgu modu.",
                });
            }

            if (mode === "search") {
                const adresQ = String(
                    req.query.adresQ ?? ""
                )
                    .trim()
                    .slice(0, 200);

                const cariQ = String(
                    req.query.cariQ ?? ""
                )
                    .trim()
                    .slice(0, 200);

                const sanitizeSearch = (value) =>
                    value
                        .replace(/[%*_(),]/g, " ")
                        .replace(/\s+/g, " ")
                        .trim();

                const safeAdres = sanitizeSearch(
                    adresQ
                );

                const safeCari = sanitizeSearch(
                    cariQ
                );

                const filters = [];

                if (safeAdres) {
                    filters.push(
                        "adres_adi=ilike." +
                            encodeURIComponent(
                                `*${safeAdres}*`
                            )
                    );
                }

                if (safeCari) {
                    filters.push(
                        "cari=ilike." +
                            encodeURIComponent(
                                `*${safeCari}*`
                            )
                    );
                }

                let searchPath =
                    "Teslim_Noktalari" +
                    "?select=" +
                    encodeURIComponent(
                        "adres_id,adres_adi,cari,cari_hesap_id"
                    );

                if (filters.length > 0) {
                    searchPath +=
                        "&" + filters.join("&");
                }

                searchPath +=
                    "&order=adres_adi.asc" +
                    "&limit=100";

                const data = await request(
                    searchPath
                );

                res.set(
                    "Cache-Control",
                    "no-store"
                );

                return res.json({
                    ok: true,
                    data: Array.isArray(data)
                        ? data
                        : [],
                });
            }

            const pageSize = 1000;
            const maxRows = 100000;
            const allRows = [];

            for (
                let offset = 0;
                offset < maxRows;
                offset += pageSize
            ) {
                const select =
                    mode === "ids"
                        ? "adres_id"
                        : "*";

                let pagePath =
                    "Teslim_Noktalari" +
                    "?select=" +
                    encodeURIComponent(select);

                if (mode === "ids") {
                    pagePath +=
                        "&adres_id=not.is.null";
                }

                pagePath +=
                    "&order=id.asc" +
                    `&offset=${offset}` +
                    `&limit=${pageSize}`;

                const page = await request(
                    pagePath
                );

                const rows = Array.isArray(page)
                    ? page
                    : [];

                allRows.push(...rows);

                if (rows.length < pageSize) {
                    break;
                }

                if (
                    offset + pageSize >=
                    maxRows
                ) {
                    throw new Error(
                        "Teslim noktalari guvenlik satir limiti asildi."
                    );
                }
            }

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json({
                ok: true,
                data: allRows,
                count: allRows.length,
            });
        } catch (error) {
            console.error(
                "Teslim noktalari read error:",
                error.message
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Teslim noktaları alınamadı.",
            });
        }
    }
);

// POST /api/data/teslim-noktalari/bulk
// Excel aktarimindan gelen yeni teslim noktalarini toplu ekler.
router.post(
    "/teslim-noktalari/bulk",
    requirePermission(
        TESLIM_NOKTALARI_SCREEN,
        "Ekle"
    ),
    async (req, res) => {
        try {
            const rows = Array.isArray(
                req.body?.rows
            )
                ? req.body.rows
                : null;

            if (!rows) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Teslim noktaları listesi zorunludur.",
                });
            }

            if (
                rows.length < 1 ||
                rows.length > 5000
            ) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Tek işlemde 1-5000 kayıt gönderilebilir.",
                });
            }

            const allowedColumns = new Set([
                "vkn",
                "cari_hesap_id",
                "cari",
                "adres_id",
                "adres_adi",
                "il",
                "ilce",
                "adres",
            ]);

            const nullableColumns = new Set([
                "cari_hesap_id",
                "cari",
                "adres_id",
                "adres_adi",
                "il",
                "ilce",
                "adres",
            ]);

            const normalizedRows = [];
            const seenAdresIds = new Set();

            for (
                let index = 0;
                index < rows.length;
                index += 1
            ) {
                const source =
                    rows[index] &&
                    typeof rows[index] === "object" &&
                    !Array.isArray(rows[index])
                        ? rows[index]
                        : null;

                if (!source) {
                    return res.status(400).json({
                        ok: false,
                        error:
                            `Geçersiz kayıt: ${index + 1}. satır.`,
                    });
                }

                const unknownColumns =
                    Object.keys(source).filter(
                        (key) =>
                            !allowedColumns.has(key)
                    );

                if (unknownColumns.length > 0) {
                    return res.status(400).json({
                        ok: false,
                        error:
                            `İzin verilmeyen alan: ${index + 1}. satır / ${unknownColumns[0]}.`,
                    });
                }

                const adresId = String(
                    source.adres_id ?? ""
                ).trim();

                if (
                    !adresId ||
                    adresId.length > 100
                ) {
                    return res.status(400).json({
                        ok: false,
                        error:
                            `Geçersiz adres_id: ${index + 1}. satır.`,
                    });
                }

                if (seenAdresIds.has(adresId)) {
                    return res.status(400).json({
                        ok: false,
                        error:
                            `Aynı adres_id istekte birden fazla kez gönderilemez: ${adresId}.`,
                    });
                }

                seenAdresIds.add(adresId);

                const normalized = {};

                for (const key of allowedColumns) {
                    if (
                        !Object.prototype.hasOwnProperty.call(
                            source,
                            key
                        )
                    ) {
                        continue;
                    }

                    const value = source[key];

                    if (
                        value === null ||
                        value === undefined
                    ) {
                        normalized[key] =
                            nullableColumns.has(key)
                                ? null
                                : "";
                        continue;
                    }

                    if (
                        typeof value !== "string" &&
                        typeof value !== "number"
                    ) {
                        return res.status(400).json({
                            ok: false,
                            error:
                                `Geçersiz alan tipi: ${index + 1}. satır / ${key}.`,
                        });
                    }

                    const normalizedValue =
                        String(value).trim();

                    if (
                        normalizedValue.length >
                        5000
                    ) {
                        return res.status(400).json({
                            ok: false,
                            error:
                                `Alan çok uzun: ${index + 1}. satır / ${key}.`,
                        });
                    }

                    normalized[key] =
                        normalizedValue;
                }

                normalized.adres_id = adresId;

                const vkn = String(
                    normalized.vkn ?? ""
                ).trim();

                if (
                    !vkn ||
                    vkn.length > 100
                ) {
                    return res.status(400).json({
                        ok: false,
                        error:
                            `Geçersiz vkn: ${index + 1}. satır.`,
                    });
                }

                normalized.vkn = vkn;

                normalizedRows.push(
                    normalized
                );
            }

            const data = await request(
                "Teslim_Noktalari",
                {
                    method: "POST",
                    headers: {
                        Prefer:
                            "resolution=ignore-duplicates,return=representation",
                    },
                    body: JSON.stringify(
                        normalizedRows
                    ),
                }
            );

            const insertedRows =
                Array.isArray(data)
                    ? data
                    : [];

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.status(201).json({
                ok: true,
                data: insertedRows,
                count: insertedRows.length,
                requestedCount:
                    normalizedRows.length,
                skippedCount:
                    normalizedRows.length -
                    insertedRows.length,
            });
        } catch (error) {
            console.error(
                "Teslim noktalari bulk create error:",
                error.message
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Teslim noktaları eklenemedi.",
            });
        }
    }
);

// ============================================================
// YENI SIPARIS - MUSTERILER / MAPPING
// ============================================================

router.get(
    "/musteriler",
    requirePermission(
        "/SiparisIslemleri/YeniSiparis",
        "Görüntüle"
    ),
    async (req, res) => {
        try {
            const aktif =
                String(req.query.aktif || "")
                    .trim()
                    .toLowerCase();

            let path =
                "musteriler" +
                "?select=" +
                encodeURIComponent(
                    [
                        "id",
                        "firma_unvani",
                        "vkn",
                        "proje_adi",
                        "urun",
                        "adres",
                        "telefon",
                        "email",
                        "aktif",
                        "created_at",
                        "updated_at",
                        "proje_karti_id",
                        "cari_firma_id",
                        "urun_id",
                        "hizmet_tipi",
                        "alt_hizmet_tipi",
                        "erp_proje_kodu",
                        "kayit_anahtari",
                    ].join(",")
                );

            if (aktif === "true" || aktif === "false") {
                path +=
                    "&aktif=eq." +
                    encodeURIComponent(aktif);
            }

            path +=
                "&order=" +
                encodeURIComponent(
                    "firma_unvani.asc,proje_adi.asc,id.asc"
                );

            const data =
                await request(path);

            return res.json({
                data: Array.isArray(data)
                    ? data
                    : [],
            });
        } catch (error) {
            console.error(
                "[dataApi] musteriler GET:",
                error?.message || error
            );

            return res.status(500).json({
                error:
                    "Müşteri kayıtları alınamadı.",
            });
        }
    }
);

router.get(
    "/yeni-siparis-mapping",
    requirePermission(
        "/SiparisIslemleri/YeniSiparis",
        "Görüntüle"
    ),
    async (req, res) => {
        try {
            const aktif =
                String(req.query.aktif || "")
                    .trim()
                    .toLowerCase();

            let path =
                "yeni_siparis_mapping" +
                "?select=" +
                encodeURIComponent(
                    [
                        "id",
                        "teslim_alan_firma",
                        "teslim_firmasi_id",
                        "teslim_noktasi_adi",
                        "teslim_noktasi_id",
                        "teslim_noktasi_il",
                        "teslim_noktasi_ilce",
                        "aktif",
                        "created_at",
                        "updated_at",
                        "musteriden_gelen",
                    ].join(",")
                );

            if (aktif === "true" || aktif === "false") {
                path +=
                    "&aktif=eq." +
                    encodeURIComponent(aktif);
            }

            path +=
                "&order=" +
                encodeURIComponent(
                    "musteriden_gelen.asc,id.asc"
                );

            const data =
                await request(path);

            return res.json({
                data: Array.isArray(data)
                    ? data
                    : [],
            });
        } catch (error) {
            console.error(
                "[dataApi] yeni-siparis-mapping GET:",
                error?.message || error
            );

            return res.status(500).json({
                error:
                    "Eşleştirme kayıtları alınamadı.",
            });
        }
    }
);

// ============================================================
// YENI_SIPARIS_MAPPING_WRITE_V1
// ============================================================

const YENI_SIPARIS_SCREEN =
    "/SiparisIslemleri/YeniSiparis";

const YENI_SIPARIS_MAPPING_COLUMNS = [
    "musteriden_gelen",
    "teslim_alan_firma",
    "teslim_firmasi_id",
    "teslim_noktasi_adi",
    "teslim_noktasi_id",
    "teslim_noktasi_il",
    "teslim_noktasi_ilce",
];

function normalizeYeniSiparisMappingPayload(
    source,
    options = {}
) {
    const input =
        source &&
        typeof source === "object" &&
        !Array.isArray(source)
            ? source
            : {};

    const partial = options.partial === true;
    const payload = {};

    for (const column of YENI_SIPARIS_MAPPING_COLUMNS) {
        if (partial && !(column in input)) {
            continue;
        }

        const raw = input[column];

        if (raw === null || raw === undefined) {
            payload[column] = "";
            continue;
        }

        if (
            typeof raw !== "string" &&
            typeof raw !== "number"
        ) {
            return {
                error:
                    `Gecersiz alan: ${column}.`,
            };
        }

        const value = String(raw).trim();

        if (value.length > 5000) {
            return {
                error:
                    `${column} en fazla 5000 karakter olabilir.`,
            };
        }

        payload[column] = value;
    }

    if (
        !partial ||
        Object.prototype.hasOwnProperty.call(
            payload,
            "teslim_alan_firma"
        )
    ) {
        if (!payload.teslim_alan_firma) {
            return {
                error:
                    "Teslim alan firma zorunludur.",
            };
        }
    }

    if (
        !partial ||
        Object.prototype.hasOwnProperty.call(
            payload,
            "teslim_noktasi_adi"
        )
    ) {
        if (!payload.teslim_noktasi_adi) {
            return {
                error:
                    "Teslim noktasi adi zorunludur.",
            };
        }
    }

    if (partial && Object.keys(payload).length === 0) {
        return {
            error:
                "Guncellenecek alan bulunamadi.",
        };
    }

    return {
        payload,
    };
}

function normalizeYeniSiparisMappingId(value) {
    const id = String(value ?? "").trim();

    if (!/^[1-9][0-9]*$/.test(id)) {
        return null;
    }

    return id;
}

router.post(
    "/yeni-siparis-mapping",
    requirePermission(
        YENI_SIPARIS_SCREEN,
        "Kaydet"
    ),
    async (req, res) => {
        try {
            const normalized =
                normalizeYeniSiparisMappingPayload(
                    req.body
                );

            if (normalized.error) {
                return res.status(400).json({
                    ok: false,
                    error: normalized.error,
                });
            }

            const payload = {
                ...normalized.payload,
                aktif: true,
            };

            const data = await request(
                "yeni_siparis_mapping",
                {
                    method: "POST",
                    headers: {
                        Prefer:
                            "return=representation",
                    },
                    body: JSON.stringify(payload),
                }
            );

            const row =
                Array.isArray(data)
                    ? data[0] || null
                    : data || null;

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
                "[dataApi] mapping create:",
                error?.message || error
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Eslestirme kaydi eklenemedi.",
            });
        }
    }
);

router.patch(
    "/yeni-siparis-mapping/:id",
    requirePermission(
        YENI_SIPARIS_SCREEN,
        "Güncelle"
    ),
    async (req, res) => {
        try {
            const id =
                normalizeYeniSiparisMappingId(
                    req.params.id
                );

            if (!id) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Gecersiz eslestirme ID.",
                });
            }

            const normalized =
                normalizeYeniSiparisMappingPayload(
                    req.body,
                    {
                        partial: true,
                    }
                );

            if (normalized.error) {
                return res.status(400).json({
                    ok: false,
                    error: normalized.error,
                });
            }

            const payload = {
                ...normalized.payload,
                updated_at:
                    new Date().toISOString(),
            };

            const data = await request(
                "yeni_siparis_mapping" +
                    "?id=eq." +
                    encodeURIComponent(id),
                {
                    method: "PATCH",
                    headers: {
                        Prefer:
                            "return=representation",
                    },
                    body: JSON.stringify(payload),
                }
            );

            if (
                !Array.isArray(data) ||
                data.length === 0
            ) {
                return res.status(404).json({
                    ok: false,
                    error:
                        "Eslestirme kaydi bulunamadi.",
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
                "[dataApi] mapping update:",
                error?.message || error
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Eslestirme kaydi guncellenemedi.",
            });
        }
    }
);

router.patch(
    "/yeni-siparis-mapping/:id/archive",
    requirePermission(
        YENI_SIPARIS_SCREEN,
        "Sil"
    ),
    async (req, res) => {
        try {
            const id =
                normalizeYeniSiparisMappingId(
                    req.params.id
                );

            if (!id) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Gecersiz eslestirme ID.",
                });
            }

            const data = await request(
                "yeni_siparis_mapping" +
                    "?id=eq." +
                    encodeURIComponent(id),
                {
                    method: "PATCH",
                    headers: {
                        Prefer:
                            "return=representation",
                    },
                    body: JSON.stringify({
                        aktif: false,
                        updated_at:
                            new Date().toISOString(),
                    }),
                }
            );

            if (
                !Array.isArray(data) ||
                data.length === 0
            ) {
                return res.status(404).json({
                    ok: false,
                    error:
                        "Eslestirme kaydi bulunamadi.",
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
                "[dataApi] mapping archive:",
                error?.message || error
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Eslestirme kaydi arsivlenemedi.",
            });
        }
    }
);

router.post(
    "/yeni-siparis-mapping/bulk",
    requirePermission(
        YENI_SIPARIS_SCREEN,
        "Excel Yükle"
    ),
    async (req, res) => {
        try {
            const rows =
                Array.isArray(req.body)
                    ? req.body
                    : req.body?.rows;

            if (
                !Array.isArray(rows) ||
                rows.length === 0
            ) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "En az bir eslestirme satiri zorunludur.",
                });
            }

            if (rows.length > 5000) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Tek istekte en fazla 5000 satir yuklenebilir.",
                });
            }

            const normalizedRows = [];

            for (
                let index = 0;
                index < rows.length;
                index += 1
            ) {
                const normalized =
                    normalizeYeniSiparisMappingPayload(
                        rows[index]
                    );

                if (normalized.error) {
                    return res.status(400).json({
                        ok: false,
                        error:
                            `${index + 1}. satir: ${normalized.error}`,
                    });
                }

                normalizedRows.push({
                    ...normalized.payload,
                    aktif: true,
                });
            }

            const insertedRows = [];

            for (
                let index = 0;
                index < normalizedRows.length;
                index += 250
            ) {
                const chunk =
                    normalizedRows.slice(
                        index,
                        index + 250
                    );

                const data = await request(
                    "yeni_siparis_mapping",
                    {
                        method: "POST",
                        headers: {
                            Prefer:
                                "return=representation",
                        },
                        body:
                            JSON.stringify(chunk),
                    }
                );

                if (Array.isArray(data)) {
                    insertedRows.push(...data);
                }
            }

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.status(201).json({
                ok: true,
                data: insertedRows,
                count: insertedRows.length,
                requestedCount:
                    normalizedRows.length,
            });
        } catch (error) {
            console.error(
                "[dataApi] mapping bulk:",
                error?.message || error
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Eslestirme kayitlari toplu olarak eklenemedi.",
            });
        }
    }
);

// YENI_SIPARIS_CUSTOMER_WRITE_V1

const YENI_SIPARIS_CUSTOMER_COLUMNS = [
    "cari_firma_id",
    "vkn",
    "urun_id",
    "proje_adi",
    "proje_karti_id",
    "firma_unvani",
    "hizmet_tipi",
    "alt_hizmet_tipi",
    "erp_proje_kodu",
];

function normalizeCustomerText(value) {
    if (value === null || value === undefined) return "";
    if (typeof value !== "string" && typeof value !== "number") {
        throw new Error("INVALID_CUSTOMER_VALUE");
    }

    const normalized = String(value).replace(/\s+/g, " ").trim();

    if (normalized.length > 5000) {
        throw new Error("CUSTOMER_VALUE_TOO_LONG");
    }

    return normalized;
}

function normalizeCustomerKey(value) {
    return normalizeCustomerText(value)
        .toLocaleUpperCase("tr-TR")
        .replace(/[\u0130I]/g, "I")
        .replace(/\u011E/g, "G")
        .replace(/\u00DC/g, "U")
        .replace(/\u015E/g, "S")
        .replace(/\u00D6/g, "O")
        .replace(/\u00C7/g, "C")
        .replace(/[^A-Z0-9]/g, "");
}

function buildCustomerRecordKeyBackend(row) {
    return [
        normalizeCustomerKey(row.cari_firma_id || row.firma_unvani),
        normalizeCustomerKey(row.proje_karti_id || row.proje_adi),
        normalizeCustomerKey(row.urun_id),
        normalizeCustomerKey(row.hizmet_tipi),
        normalizeCustomerKey(row.alt_hizmet_tipi),
        normalizeCustomerKey(row.erp_proje_kodu),
    ].join("::");
}

function normalizeCustomerPayload(source, options = {}) {
    const { partial = false } = options;

    if (!source || typeof source !== "object" || Array.isArray(source)) {
        throw new Error("INVALID_CUSTOMER_PAYLOAD");
    }

    const payload = {};

    for (const column of YENI_SIPARIS_CUSTOMER_COLUMNS) {
        if (!partial || Object.prototype.hasOwnProperty.call(source, column)) {
            payload[column] = normalizeCustomerText(source[column]);
        }
    }

    if (!partial && !payload.firma_unvani) {
        throw new Error("CUSTOMER_COMPANY_REQUIRED");
    }

    if (
        partial &&
        Object.prototype.hasOwnProperty.call(payload, "firma_unvani") &&
        !payload.firma_unvani
    ) {
        throw new Error("CUSTOMER_COMPANY_REQUIRED");
    }

    if (partial && Object.keys(payload).length === 0) {
        throw new Error("EMPTY_CUSTOMER_UPDATE");
    }

    return payload;
}

function normalizeCustomerId(value) {
    const id = String(value || "").trim();

    if (
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)
    ) {
        throw new Error("INVALID_CUSTOMER_ID");
    }

    return id;
}

function customerBadRequest(res) {
    return res.status(400).json({
        error: "Gecersiz musteri verisi.",
    });
}

router.post(
    "/musteriler",
    requirePermission(YENI_SIPARIS_SCREEN, "Kaydet"),
    async (req, res) => {
        try {
            const payload = normalizeCustomerPayload(req.body);

            payload.aktif = true;
            payload.updated_at = new Date().toISOString();
            payload.kayit_anahtari = buildCustomerRecordKeyBackend(payload);

            const rows = await request("musteriler", {
                method: "POST",
                headers: {
                    Prefer: "return=representation",
                },
                body: JSON.stringify(payload),
            });

            res.set("Cache-Control", "no-store");

            return res.status(201).json({
                data: Array.isArray(rows) ? rows[0] || null : rows,
            });
        } catch (error) {
            if (
                [
                    "INVALID_CUSTOMER_PAYLOAD",
                    "INVALID_CUSTOMER_VALUE",
                    "CUSTOMER_VALUE_TOO_LONG",
                    "CUSTOMER_COMPANY_REQUIRED",
                ].includes(error?.message)
            ) {
                return customerBadRequest(res);
            }

            console.error("Yeni Siparis musteri create error:", error);
            return res.status(500).json({
                error: "Musteri kaydi olusturulamadi.",
            });
        }
    }
);

router.patch(
    "/musteriler/:id",
    requirePermission(YENI_SIPARIS_SCREEN, "Güncelle"),
    async (req, res) => {
        try {
            const id = normalizeCustomerId(req.params.id);
            const changes = normalizeCustomerPayload(req.body, {
                partial: true,
            });

            // kayit_anahtari, kaydin tum alanlarina bagli oldugu icin
            // once mevcut kaydi service-role ile okuyup yeni anahtari
            // backend tarafinda yeniden uretiyoruz.
            const existingRows = await request(
                `musteriler?select=${encodeURIComponent(
                    YENI_SIPARIS_CUSTOMER_COLUMNS.join(",")
                )}&id=eq.${encodeURIComponent(id)}&limit=1`
            );

            const existing =
                Array.isArray(existingRows) && existingRows.length
                    ? existingRows[0]
                    : null;

            if (!existing) {
                return res.status(404).json({
                    error: "Musteri kaydi bulunamadi.",
                });
            }

            const merged = {
                ...existing,
                ...changes,
            };

            if (!normalizeCustomerText(merged.firma_unvani)) {
                return customerBadRequest(res);
            }

            const payload = {
                ...changes,
                aktif: true,
                updated_at: new Date().toISOString(),
                kayit_anahtari: buildCustomerRecordKeyBackend(merged),
            };

            const rows = await request(
                `musteriler?id=eq.${encodeURIComponent(id)}`,
                {
                    method: "PATCH",
                    headers: {
                        Prefer: "return=representation",
                    },
                    body: JSON.stringify(payload),
                }
            );

            if (!Array.isArray(rows) || rows.length === 0) {
                return res.status(404).json({
                    error: "Musteri kaydi bulunamadi.",
                });
            }

            res.set("Cache-Control", "no-store");

            return res.json({
                data: rows[0],
            });
        } catch (error) {
            if (
                [
                    "INVALID_CUSTOMER_ID",
                    "INVALID_CUSTOMER_PAYLOAD",
                    "INVALID_CUSTOMER_VALUE",
                    "CUSTOMER_VALUE_TOO_LONG",
                    "CUSTOMER_COMPANY_REQUIRED",
                    "EMPTY_CUSTOMER_UPDATE",
                ].includes(error?.message)
            ) {
                return customerBadRequest(res);
            }

            console.error("Yeni Siparis musteri update error:", error);
            return res.status(500).json({
                error: "Musteri kaydi guncellenemedi.",
            });
        }
    }
);

router.patch(
    "/musteriler/:id/archive",
    requirePermission(YENI_SIPARIS_SCREEN, "Sil"),
    async (req, res) => {
        try {
            const id = normalizeCustomerId(req.params.id);

            const rows = await request(
                `musteriler?id=eq.${encodeURIComponent(id)}`,
                {
                    method: "PATCH",
                    headers: {
                        Prefer: "return=representation",
                    },
                    body: JSON.stringify({
                        aktif: false,
                        updated_at: new Date().toISOString(),
                    }),
                }
            );

            if (!Array.isArray(rows) || rows.length === 0) {
                return res.status(404).json({
                    error: "Musteri kaydi bulunamadi.",
                });
            }

            res.set("Cache-Control", "no-store");

            return res.json({
                data: rows[0],
            });
        } catch (error) {
            if (error?.message === "INVALID_CUSTOMER_ID") {
                return customerBadRequest(res);
            }

            console.error("Yeni Siparis musteri archive error:", error);
            return res.status(500).json({
                error: "Musteri kaydi pasife alinamadi.",
            });
        }
    }
);

router.post(
    "/musteriler/bulk",
    requirePermission(YENI_SIPARIS_SCREEN, "Excel Yükle"),
    async (req, res) => {
        try {
            const sourceRows = Array.isArray(req.body)
                ? req.body
                : req.body?.rows;

            if (
                !Array.isArray(sourceRows) ||
                sourceRows.length < 1 ||
                sourceRows.length > 5000
            ) {
                return customerBadRequest(res);
            }

            const deduped = new Map();

            for (const source of sourceRows) {
                const row = normalizeCustomerPayload(source);

                row.aktif = true;
                row.updated_at = new Date().toISOString();
                row.kayit_anahtari = buildCustomerRecordKeyBackend(row);

                const previous = deduped.get(row.kayit_anahtari);

                if (!previous) {
                    deduped.set(row.kayit_anahtari, row);
                    continue;
                }

                deduped.set(row.kayit_anahtari, {
                    ...previous,
                    ...row,
                    cari_firma_id:
                        row.cari_firma_id || previous.cari_firma_id || "",
                    vkn:
                        row.vkn || previous.vkn || "",
                    urun_id:
                        row.urun_id || previous.urun_id || "",
                    proje_karti_id:
                        row.proje_karti_id || previous.proje_karti_id || "",
                    hizmet_tipi:
                        row.hizmet_tipi || previous.hizmet_tipi || "",
                    alt_hizmet_tipi:
                        row.alt_hizmet_tipi ||
                        previous.alt_hizmet_tipi ||
                        "",
                    erp_proje_kodu:
                        row.erp_proje_kodu ||
                        previous.erp_proje_kodu ||
                        "",
                    aktif: true,
                    updated_at: new Date().toISOString(),
                });
            }

            const uniqueRows = Array.from(deduped.values());
            const inserted = [];
            const chunkSize = 250;

            for (let i = 0; i < uniqueRows.length; i += chunkSize) {
                const chunk = uniqueRows.slice(i, i + chunkSize);

                const rows = await request(
                    "musteriler?on_conflict=kayit_anahtari",
                    {
                        method: "POST",
                        headers: {
                            Prefer:
                                "resolution=merge-duplicates,return=representation",
                        },
                        body: JSON.stringify(chunk),
                    }
                );

                if (Array.isArray(rows)) {
                    inserted.push(...rows);
                }
            }

            res.set("Cache-Control", "no-store");

            return res.json({
                data: inserted,
                requestedCount: sourceRows.length,
                processedCount: uniqueRows.length,
                duplicateCount:
                    sourceRows.length - uniqueRows.length,
            });
        } catch (error) {
            if (
                [
                    "INVALID_CUSTOMER_PAYLOAD",
                    "INVALID_CUSTOMER_VALUE",
                    "CUSTOMER_VALUE_TOO_LONG",
                    "CUSTOMER_COMPANY_REQUIRED",
                ].includes(error?.message)
            ) {
                return customerBadRequest(res);
            }

            console.error("Yeni Siparis musteri bulk error:", error);
            return res.status(500).json({
                error: "Musteri Excel aktarimi tamamlanamadi.",
            });
        }
    }
);

// YAKIT_HESAPLAMA_READ_API_V1
const YAKIT_HESAPLAMA_SCREEN = "/finans/yakit-hesaplama";

const YAKIT_TARIFE_TABLES = Object.freeze({
    alis: "yakit_alis_tarifeleri",
    satis: "yakit_satis_tarifeleri",
});

function normalizeYakitMusteriId(value) {
    const normalized = String(value ?? "").trim();

    if (!normalized || normalized.length > 100) {
        const error = new Error("INVALID_YAKIT_MUSTERI_ID");
        throw error;
    }

    return normalized;
}

function normalizeYakitTarifeTipi(value) {
    const normalized = String(value ?? "")
        .trim()
        .toLocaleLowerCase("tr-TR");

    if (!Object.prototype.hasOwnProperty.call(YAKIT_TARIFE_TABLES, normalized)) {
        const error = new Error("INVALID_YAKIT_TARIFE_TIPI");
        throw error;
    }

    return normalized;
}

function yakitReadBadRequest(res) {
    return res.status(400).json({
        error: "Geçersiz yakıt hesaplama isteği.",
    });
}

router.get(
    "/yakit-hesaplama/musteriler",
    requirePermission(YAKIT_HESAPLAMA_SCREEN, "Görüntüle"),
    async (_req, res) => {
        try {
            const rows = await request(
                "yakit_musterileri?select=id,musteri_adi,kod&order=musteri_adi.asc"
            );

            res.set("Cache-Control", "no-store");

            return res.json({
                data: Array.isArray(rows) ? rows : [],
            });
        } catch (error) {
            console.error("Yakit hesaplama musteri list error:", error);

            return res.status(500).json({
                error: "Yakıt müşterileri alınamadı.",
            });
        }
    }
);

router.get(
    "/yakit-hesaplama/tarifeler",
    requirePermission(YAKIT_HESAPLAMA_SCREEN, "Görüntüle"),
    async (req, res) => {
        try {
            const musteriId = normalizeYakitMusteriId(
                req.query.musteriId
            );

            const tarifeTipi = normalizeYakitTarifeTipi(
                req.query.tip
            );

            const table = YAKIT_TARIFE_TABLES[tarifeTipi];

            const rows = await request(
                `${table}?select=*&musteri_id=eq.${encodeURIComponent(
                    musteriId
                )}&aktif=eq.true&order=id.asc`
            );

            res.set("Cache-Control", "no-store");

            return res.json({
                data: Array.isArray(rows) ? rows : [],
            });
        } catch (error) {
            if (
                [
                    "INVALID_YAKIT_MUSTERI_ID",
                    "INVALID_YAKIT_TARIFE_TIPI",
                ].includes(error?.message)
            ) {
                return yakitReadBadRequest(res);
            }

            console.error("Yakit hesaplama tarife list error:", error);

            return res.status(500).json({
                error: "Yakıt tarifeleri alınamadı.",
            });
        }
    }
);

router.get(
    "/yakit-hesaplama/gecmis",
    requirePermission(YAKIT_HESAPLAMA_SCREEN, "Görüntüle"),
    async (req, res) => {
        try {
            const musteriId = normalizeYakitMusteriId(
                req.query.musteriId
            );

            const params = new URLSearchParams();

            params.set("select", "*");
            params.set("musteri_id", `eq.${musteriId}`);
            params.set("order", "created_at.desc");

            const rawLimit = String(
                req.query.limit ?? ""
            ).trim();

            if (rawLimit) {
                if (!/^[1-9][0-9]*$/.test(rawLimit)) {
                    return yakitReadBadRequest(res);
                }

                const limit = Number(rawLimit);

                if (
                    !Number.isSafeInteger(limit) ||
                    limit < 1 ||
                    limit > 5000
                ) {
                    return yakitReadBadRequest(res);
                }

                params.set("limit", String(limit));
            }

            const rows = await request(
                `yakit_ton_tl_gecmisi?${params.toString()}`
            );

            res.set("Cache-Control", "no-store");

            return res.json({
                data: Array.isArray(rows) ? rows : [],
            });
        } catch (error) {
            if (error?.message === "INVALID_YAKIT_MUSTERI_ID") {
                return yakitReadBadRequest(res);
            }

            console.error("Yakit hesaplama gecmis list error:", error);

            return res.status(500).json({
                error: "Yakıt fiyat geçmişi alınamadı.",
            });
        }
    }
);

// YAKIT_HESAPLAMA_CREATE_API_V1

function normalizeYakitTarifeText(
    value,
    {
        required = false,
        maxLength = 500,
    } = {}
) {
    const normalized = String(value ?? "")
        .replace(/\s+/g, " ")
        .trim();

    if (required && !normalized) {
        throw new Error("INVALID_YAKIT_TARIFE_PAYLOAD");
    }

    if (normalized.length > maxLength) {
        throw new Error("INVALID_YAKIT_TARIFE_PAYLOAD");
    }

    return normalized || null;
}

function normalizeYakitTonTl(value) {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        throw new Error("INVALID_YAKIT_TARIFE_PAYLOAD");
    }

    const normalized =
        typeof value === "string"
            ? value.trim().replace(",", ".")
            : value;

    const numeric = Number(normalized);

    if (
        !Number.isFinite(numeric) ||
        numeric < 0 ||
        numeric > 1000000000
    ) {
        throw new Error("INVALID_YAKIT_TARIFE_PAYLOAD");
    }

    return numeric;
}

function normalizeYakitTarifeRow(
    row,
    expectedMusteriId
) {
    if (
        !row ||
        typeof row !== "object" ||
        Array.isArray(row)
    ) {
        throw new Error("INVALID_YAKIT_TARIFE_PAYLOAD");
    }

    const allowedKeys = new Set([
        "musteri_id",
        "il",
        "ilce",
        "koy_mahalle",
        "ton_tl",
    ]);

    const unknownKeys = Object.keys(row).filter(
        (key) => !allowedKeys.has(key)
    );

    if (unknownKeys.length) {
        throw new Error("INVALID_YAKIT_TARIFE_PAYLOAD");
    }

    const musteriId = normalizeYakitMusteriId(
        row.musteri_id
    );

    if (musteriId !== expectedMusteriId) {
        throw new Error("INVALID_YAKIT_TARIFE_PAYLOAD");
    }

    return {
        musteri_id: musteriId,

        il: normalizeYakitTarifeText(
            row.il,
            {
                required: true,
                maxLength: 250,
            }
        ),

        ilce: normalizeYakitTarifeText(
            row.ilce,
            {
                required: true,
                maxLength: 250,
            }
        ),

        koy_mahalle: normalizeYakitTarifeText(
            row.koy_mahalle,
            {
                required: false,
                maxLength: 500,
            }
        ),

        ton_tl: normalizeYakitTonTl(
            row.ton_tl
        ),
    };
}

function yakitCreateBadRequest(res) {
    return res.status(400).json({
        error: "Geçersiz yakıt tarifesi verisi.",
    });
}

router.post(
    "/yakit-hesaplama/tarifeler",
    requirePermission(
        YAKIT_HESAPLAMA_SCREEN,
        "Kaydet"
    ),
    async (req, res) => {
        try {
            const musteriId =
                normalizeYakitMusteriId(
                    req.body?.musteriId
                );

            const tarifeTipi =
                normalizeYakitTarifeTipi(
                    req.body?.tip
                );

            const row =
                normalizeYakitTarifeRow(
                    req.body?.row,
                    musteriId
                );

            const table =
                YAKIT_TARIFE_TABLES[
                    tarifeTipi
                ];

            const data = await request(
                table,
                {
                    method: "POST",
                    headers: {
                        Prefer:
                            "return=representation",
                    },
                    body: JSON.stringify(
                        row
                    ),
                }
            );

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.status(201).json({
                data:
                    Array.isArray(data)
                        ? data
                        : [],
            });
        } catch (error) {
            if (
                [
                    "INVALID_YAKIT_MUSTERI_ID",
                    "INVALID_YAKIT_TARIFE_TIPI",
                    "INVALID_YAKIT_TARIFE_PAYLOAD",
                ].includes(error?.message)
            ) {
                return yakitCreateBadRequest(
                    res
                );
            }

            console.error(
                "Yakit tarife create error:",
                error
            );

            return res.status(500).json({
                error:
                    "Yakıt tarifesi kaydedilemedi.",
            });
        }
    }
);

router.post(
    "/yakit-hesaplama/tarifeler/bulk",
    requirePermission(
        YAKIT_HESAPLAMA_SCREEN,
        "Excel Yükle"
    ),
    async (req, res) => {
        try {
            const musteriId =
                normalizeYakitMusteriId(
                    req.body?.musteriId
                );

            const tarifeTipi =
                normalizeYakitTarifeTipi(
                    req.body?.tip
                );

            const rows =
                req.body?.rows;

            if (
                !Array.isArray(rows) ||
                rows.length < 1 ||
                rows.length > 5000
            ) {
                return yakitCreateBadRequest(
                    res
                );
            }

            const normalizedRows =
                rows.map((row) =>
                    normalizeYakitTarifeRow(
                        row,
                        musteriId
                    )
                );

            const table =
                YAKIT_TARIFE_TABLES[
                    tarifeTipi
                ];

            const inserted = [];

            for (
                let index = 0;
                index < normalizedRows.length;
                index += 500
            ) {
                const chunk =
                    normalizedRows.slice(
                        index,
                        index + 500
                    );

                const data =
                    await request(
                        table,
                        {
                            method: "POST",
                            headers: {
                                Prefer:
                                    "return=representation",
                            },
                            body:
                                JSON.stringify(
                                    chunk
                                ),
                        }
                    );

                if (Array.isArray(data)) {
                    inserted.push(...data);
                }
            }

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.status(201).json({
                inserted:
                    inserted.length,
                data: inserted,
            });
        } catch (error) {
            if (
                [
                    "INVALID_YAKIT_MUSTERI_ID",
                    "INVALID_YAKIT_TARIFE_TIPI",
                    "INVALID_YAKIT_TARIFE_PAYLOAD",
                ].includes(error?.message)
            ) {
                return yakitCreateBadRequest(
                    res
                );
            }

            console.error(
                "Yakit tarife bulk create error:",
                error
            );

            return res.status(500).json({
                error:
                    "Yakıt tarifeleri Excel'den aktarılamadı.",
            });
        }
    }
);


function normalizeYakitUpdateNumber(
    value,
    {
        min = -1000000000,
        max = 1000000000,
    } = {}
) {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        throw new Error(
            "INVALID_YAKIT_UPDATE_PAYLOAD"
        );
    }

    const normalized =
        typeof value === "string"
            ? value.trim().replace(",", ".")
            : value;

    const numeric = Number(normalized);

    if (
        !Number.isFinite(numeric) ||
        numeric < min ||
        numeric > max
    ) {
        throw new Error(
            "INVALID_YAKIT_UPDATE_PAYLOAD"
        );
    }

    return numeric;
}

function normalizeYakitUpdateRows(rows) {
    if (
        !Array.isArray(rows) ||
        rows.length < 1 ||
        rows.length > 5000
    ) {
        throw new Error(
            "INVALID_YAKIT_UPDATE_PAYLOAD"
        );
    }

    const seenIds = new Set();

    return rows.map((row) => {
        if (
            !row ||
            typeof row !== "object" ||
            Array.isArray(row)
        ) {
            throw new Error(
                "INVALID_YAKIT_UPDATE_PAYLOAD"
            );
        }

        const allowedKeys =
            new Set([
                "id",
                "yeni_ton_tl",
            ]);

        const unknownKeys =
            Object.keys(row).filter(
                (key) =>
                    !allowedKeys.has(key)
            );

        if (unknownKeys.length) {
            throw new Error(
                "INVALID_YAKIT_UPDATE_PAYLOAD"
            );
        }

        const id = Number(row.id);

        if (
            !Number.isSafeInteger(id) ||
            id < 1
        ) {
            throw new Error(
                "INVALID_YAKIT_UPDATE_PAYLOAD"
            );
        }

        const idKey = String(id);

        if (seenIds.has(idKey)) {
            throw new Error(
                "INVALID_YAKIT_UPDATE_PAYLOAD"
            );
        }

        seenIds.add(idKey);

        const yeniTonTl =
            normalizeYakitUpdateNumber(
                row.yeni_ton_tl,
                {
                    min: 0,
                    max: 1000000000,
                }
            );

        return {
            id,
            yeni_ton_tl: yeniTonTl,
        };
    });
}

// YAKIT_HESAPLAMA_UPDATE_API_V2
router.post(
    "/yakit-hesaplama/tarifeler/guncelle",
    requirePermission(
        YAKIT_HESAPLAMA_SCREEN,
        "Güncelle"
    ),
    async (req, res) => {
        try {
            const musteriId =
                normalizeYakitMusteriId(
                    req.body?.musteriId
                );

            const rawAlisRows =
                req.body?.alisRows;

            const rawSatisRows =
                req.body?.satisRows;

            if (
                !Array.isArray(rawAlisRows) ||
                !Array.isArray(rawSatisRows)
            ) {
                throw new Error(
                    "INVALID_YAKIT_UPDATE_PAYLOAD"
                );
            }

            const totalRows =
                rawAlisRows.length +
                rawSatisRows.length;

            if (
                totalRows < 1 ||
                totalRows > 5000
            ) {
                throw new Error(
                    "INVALID_YAKIT_UPDATE_PAYLOAD"
                );
            }

            const alisRows =
                rawAlisRows.length
                    ? normalizeYakitUpdateRows(
                        rawAlisRows
                    )
                    : [];

            const satisRows =
                rawSatisRows.length
                    ? normalizeYakitUpdateRows(
                        rawSatisRows
                    )
                    : [];


            const eskiYakitFiyati =
                normalizeYakitUpdateNumber(
                    req.body?.eskiYakitFiyati,
                    {
                        min: 0,
                        max: 1000000000,
                    }
                );

            const yeniYakitFiyati =
                normalizeYakitUpdateNumber(
                    req.body?.yeniYakitFiyati,
                    {
                        min: 0,
                        max: 1000000000,
                    }
                );

            const yakitDegisimOrani =
                normalizeYakitUpdateNumber(
                    req.body?.yakitDegisimOrani
                );

            const uygulananArtisOrani =
                normalizeYakitUpdateNumber(
                    req.body?.uygulananArtisOrani
                );

            const data = await request(
                "rpc/yakit_tarife_guncelle",
                {
                    method: "POST",
                    body: JSON.stringify({
                        p_musteri_id:
                            Number(musteriId),

                        p_alis_satirlar:
                            alisRows,

                        p_satis_satirlar:
                            satisRows,

                        p_eski_yakit_fiyati:
                            eskiYakitFiyati,

                        p_yeni_yakit_fiyati:
                            yeniYakitFiyati,

                        p_yakit_degisim_orani:
                            yakitDegisimOrani,

                        p_uygulanan_artis_orani:
                            uygulananArtisOrani,
                    }),
                }
            );

            const updated =
                Number(data ?? 0);

            if (
                !Number.isSafeInteger(updated) ||
                updated !== totalRows
            ) {
                throw new Error(
                    "YAKIT_UPDATE_COUNT_MISMATCH"
                );
            }

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json({
                updated,
            });
        } catch (error) {
            if (
                [
                    "INVALID_YAKIT_MUSTERI_ID",
                    "INVALID_YAKIT_UPDATE_PAYLOAD",
                ].includes(error?.message)
            ) {
                return res.status(400).json({
                    error:
                        "Geçersiz yakıt güncelleme verisi.",
                });
            }

            console.error(
                "Yakit tarife update error:",
                error
            );

            return res.status(500).json({
                error:
                    "Yakıt tarifeleri güncellenemedi.",
            });
        }
    }
);
// YAKIT_HESAPLAMA_UNDO_API_V1
router.post(
    "/yakit-hesaplama/tarifeler/geri-al",
    requirePermission(
        YAKIT_HESAPLAMA_SCREEN,
        "Güncelle"
    ),
    async (req, res) => {
        try {
            const musteriId =
                normalizeYakitMusteriId(
                    req.body?.musteriId
                );

            const data = await request(
                "rpc/yakit_tarife_geri_al",
                {
                    method: "POST",
                    body: JSON.stringify({
                        p_musteri_id:
                            Number(musteriId),
                    }),
                }
            );

            if (
                !data ||
                typeof data !== "object" ||
                Array.isArray(data)
            ) {
                throw new Error(
                    "YAKIT_UNDO_INVALID_RESPONSE"
                );
            }

            if (data.found === false) {
                res.set(
                    "Cache-Control",
                    "no-store"
                );

                return res.json({
                    found: false,
                    restored: 0,
                });
            }

            const restored =
                Number(data.restored);

            if (
                data.found !== true ||
                !Number.isSafeInteger(restored) ||
                restored < 1 ||
                restored > 1000
            ) {
                throw new Error(
                    "YAKIT_UNDO_INVALID_RESPONSE"
                );
            }

            const eskiYakitFiyati =
                normalizeYakitUpdateNumber(
                    data.eskiYakitFiyati,
                    {
                        min: 0,
                        max: 1000000000,
                    }
                );

            const yeniYakitFiyati =
                normalizeYakitUpdateNumber(
                    data.yeniYakitFiyati,
                    {
                        min: 0,
                        max: 1000000000,
                    }
                );

            const yakitDegisimOrani =
                normalizeYakitUpdateNumber(
                    data.yakitDegisimOrani
                );

            const uygulananArtisOrani =
                normalizeYakitUpdateNumber(
                    data.uygulananArtisOrani
                );

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json({
                found: true,
                restored,
                eskiYakitFiyati,
                yeniYakitFiyati,
                yakitDegisimOrani,
                uygulananArtisOrani,
                createdAt:
                    data.createdAt ?? null,
            });
        } catch (error) {
            if (
                error?.message ===
                "INVALID_YAKIT_MUSTERI_ID"
            ) {
                return res.status(400).json({
                    error:
                        "Geçersiz yakıt müşterisi.",
                });
            }

            console.error(
                "Yakit tarife undo error:",
                error
            );

            return res.status(500).json({
                error:
                    "Son yakıt tarife güncellemesi geri alınamadı.",
            });
        }
    }
);

module.exports = router;
