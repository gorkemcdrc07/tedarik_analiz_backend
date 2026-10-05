const express = require("express");
const { request } = require("./supabase");
const { requireAuth } = require("./middleware");
const { requirePermission } = require("./permissions");

const router = express.Router();

router.use(requireAuth);

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
    "/musteriler",
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
    "/tarifeler",
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
    "/gecmis",
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
    "/tarifeler",
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
    "/tarifeler/bulk",
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
    "/tarifeler/guncelle",
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
    "/tarifeler/geri-al",
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

// EFOR_CAY_CENTRAL_READ_API_V1
// Supabase is the source of truth. This endpoint is read-only.
// ============================================================
router.get(
    "/efor-cay/:musteriId",
    requirePermission(
        YAKIT_HESAPLAMA_SCREEN,
        "Görüntüle"
    ),
    async (req, res) => {
        try {
            const musteriId =
                normalizeYakitMusteriId(
                    req.params.musteriId
                );

            const encodedMusteriId =
                encodeURIComponent(musteriId);

            const [
                durumRows,
                tarifeRows,
                gecmisRows,
            ] = await Promise.all([
                request(
                    "efor_cay_yakit_durum" +
                    "?select=musteri_id,kabul_edilen_yakit,updated_at" +
                    "&musteri_id=eq." +
                    encodedMusteriId +
                    "&limit=1"
                ),
                request(
                    "efor_cay_tarifeleri" +
                    "?select=id,musteri_id,sira,yukleme,varis,arac_tipi,tir,updated_at" +
                    "&musteri_id=eq." +
                    encodedMusteriId +
                    "&order=sira.asc"
                ),
                request(
                    "efor_cay_yakit_gecmisi" +
                    "?select=id,musteri_id,eski_yakit_fiyati,yeni_yakit_fiyati,degisim_orani,uygulanan_oran,eski_tarifeler,yeni_tarifeler,created_at" +
                    "&musteri_id=eq." +
                    encodedMusteriId +
                    "&order=created_at.desc" +
                    "&limit=100"
                ),
            ]);

            const durum =
                Array.isArray(durumRows) &&
                durumRows.length > 0
                    ? durumRows[0]
                    : null;

            const tarifeler =
                Array.isArray(tarifeRows)
                    ? tarifeRows
                    : [];

            const gecmis =
                Array.isArray(gecmisRows)
                    ? gecmisRows
                    : [];

            const kabulEdilenYakit =
                durum?.kabul_edilen_yakit == null
                    ? null
                    : Number(
                          durum.kabul_edilen_yakit
                      );

            if (
                kabulEdilenYakit !== null &&
                (
                    !Number.isFinite(
                        kabulEdilenYakit
                    ) ||
                    kabulEdilenYakit <= 0
                )
            ) {
                throw new Error(
                    "EFOR_CAY_INVALID_ACCEPTED_FUEL"
                );
            }

            const normalizedTarifeler =
                tarifeler.map((row) => {
                    const sira =
                        Number(row.sira);

                    const tir =
                        Number(row.tir);

                    if (
                        !Number.isSafeInteger(sira) ||
                        sira < 1 ||
                        !Number.isFinite(tir) ||
                        tir < 0
                    ) {
                        throw new Error(
                            "EFOR_CAY_INVALID_TARIFF"
                        );
                    }

                    return {
                        id: row.id,
                        musteriId:
                            row.musteri_id,
                        sira,
                        yukleme:
                            row.yukleme ?? "",
                        varis:
                            row.varis ?? "",
                        aracTipi:
                            row.arac_tipi ??
                            "TIR",
                        tir,
                        updatedAt:
                            row.updated_at ??
                            null,
                    };
                });

            const normalizedGecmis =
                gecmis.map((row) => ({
                    id: row.id,
                    musteriId:
                        row.musteri_id,

                    eskiYakitFiyati:
                        row.eski_yakit_fiyati ==
                        null
                            ? null
                            : Number(
                                  row.eski_yakit_fiyati
                              ),

                    yeniYakitFiyati:
                        row.yeni_yakit_fiyati ==
                        null
                            ? null
                            : Number(
                                  row.yeni_yakit_fiyati
                              ),

                    degisimOrani:
                        row.degisim_orani == null
                            ? null
                            : Number(
                                  row.degisim_orani
                              ),

                    uygulananOran:
                        row.uygulanan_oran ==
                        null
                            ? null
                            : Number(
                                  row.uygulanan_oran
                              ),

                    eskiTarifeler:
                        row.eski_tarifeler ??
                        null,

                    yeniTarifeler:
                        row.yeni_tarifeler ??
                        null,

                    createdAt:
                        row.created_at ??
                        null,
                }));

            const initialized =
                durum !== null &&
                kabulEdilenYakit !== null &&
                normalizedTarifeler.length > 0;

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json({
                initialized,
                musteriId,
                kabulEdilenYakit,
                updatedAt:
                    durum?.updated_at ??
                    null,
                tarifeler:
                    normalizedTarifeler,
                gecmis:
                    normalizedGecmis,
            });
        } catch (error) {
            if (
                error?.message ===
                "INVALID_YAKIT_MUSTERI_ID"
            ) {
                return res.status(400).json({
                    error:
                        "Gecersiz yakit musterisi.",
                });
            }

            console.error(
                "EFOR Cay central read error:",
                error
            );

            return res.status(500).json({
                error:
                    "EFOR CAY merkezi verileri alinamadi.",
            });
        }
    }
);


// ============================================================
// EFOR_CAY_CENTRAL_WRITE_API_V1
// Supabase is the source of truth.
// Rule calculation is performed inside the database RPC.
// ============================================================

// ------------------------------------------------------------
// UPDATE
// ------------------------------------------------------------
router.post(
    "/efor-cay/update",
    requirePermission(
        YAKIT_HESAPLAMA_SCREEN,
        "Güncelle"
    ),
    async (req, res) => {
        try {
            const rawMusteriId =
                String(
                    req.body?.musteriId ?? ""
                ).trim();

            if (
                !/^[1-9][0-9]*$/.test(
                    rawMusteriId
                )
            ) {
                return res.status(400).json({
                    error:
                        "Gecersiz EFOR CAY musteri id.",
                });
            }

            const musteriId =
                Number(rawMusteriId);

            if (
                !Number.isSafeInteger(
                    musteriId
                )
            ) {
                return res.status(400).json({
                    error:
                        "Gecersiz EFOR CAY musteri id.",
                });
            }

            const yeniYakit =
                Number(
                    req.body?.yeniYakit
                );

            if (
                !Number.isFinite(yeniYakit) ||
                yeniYakit <= 0 ||
                yeniYakit > 1000000
            ) {
                return res.status(400).json({
                    error:
                        "Gecersiz EFOR CAY yakit fiyati.",
                });
            }

            const data = await request(
                "rpc/efor_cay_guncelle",
                {
                    method: "POST",
                    body: JSON.stringify({
                        p_musteri_id:
                            musteriId,
                        p_yeni_yakit:
                            yeniYakit,
                    }),
                }
            );

            if (
                !data ||
                typeof data !== "object" ||
                Array.isArray(data)
            ) {
                throw new Error(
                    "EFOR_CAY_UPDATE_INVALID_RESPONSE"
                );
            }

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json(data);
        } catch (error) {
            console.error(
                "EFOR Cay central update error:",
                error
            );

            return res.status(500).json({
                error:
                    "EFOR CAY merkezi guncelleme tamamlanamadi.",
            });
        }
    }
);


// ------------------------------------------------------------
// UNDO
// ------------------------------------------------------------
router.post(
    "/efor-cay/undo",
    requirePermission(
        YAKIT_HESAPLAMA_SCREEN,
        "Güncelle"
    ),
    async (req, res) => {
        try {
            const rawMusteriId =
                String(
                    req.body?.musteriId ?? ""
                ).trim();

            if (
                !/^[1-9][0-9]*$/.test(
                    rawMusteriId
                )
            ) {
                return res.status(400).json({
                    error:
                        "Gecersiz EFOR CAY musteri id.",
                });
            }

            const musteriId =
                Number(rawMusteriId);

            if (
                !Number.isSafeInteger(
                    musteriId
                )
            ) {
                return res.status(400).json({
                    error:
                        "Gecersiz EFOR CAY musteri id.",
                });
            }

            const data = await request(
                "rpc/efor_cay_geri_al",
                {
                    method: "POST",
                    body: JSON.stringify({
                        p_musteri_id:
                            musteriId,
                    }),
                }
            );

            if (
                !data ||
                typeof data !== "object" ||
                Array.isArray(data)
            ) {
                throw new Error(
                    "EFOR_CAY_UNDO_INVALID_RESPONSE"
                );
            }

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json(data);
        } catch (error) {
            console.error(
                "EFOR Cay central undo error:",
                error
            );

            return res.status(500).json({
                error:
                    "EFOR CAY merkezi geri alma tamamlanamadi.",
            });
        }
    }
);

module.exports = router;
