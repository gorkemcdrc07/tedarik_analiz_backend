const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");
const path = require("path");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const adminUsersRouter = require("./auth/adminUsers");
const dataApiRouter = require("./auth/dataApi");
const { request: supabaseRequest } = require("./auth/supabase");
// .env dosyasÄ±nÄ± process.cwd() yerine doÄŸrudan server klasÃ¶rÃ¼nden yÃ¼kle.
// BÃ¶ylece `npm --prefix server start` ve farklÄ± Ã§alÄ±ÅŸma dizinlerinde aynÄ± davranÄ±r.
const envPath = path.resolve(__dirname, ".env");
require("dotenv").config({ path: envPath, override: true });

const app = express();

app.set("trust proxy", 1);

app.use(
    helmet({
        crossOriginResourcePolicy: {
            policy: "cross-origin",
        },
    })
);

const allowedOrigins = new Set([
    "https://tedarik-analiz.vercel.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]);

app.use(
    cors({
        origin(origin, callback) {
            // Origin olmayan server-to-server / same-origin istekleri engelleme.
            if (!origin) {
                return callback(null, true);
            }

            if (allowedOrigins.has(origin)) {
                return callback(null, true);
            }

            return callback(
                new Error("CORS origin not allowed.")
            );
        },
        credentials: true,
        methods: [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
        ],
        allowedHeaders: [
            "Content-Type",
            "Authorization",
        ],
    })
);

app.use(cookieParser());

app.use(
    express.json({
        limit: "1mb",
    })
);

// ===============================
// 2FA AUTHENTICATION
// ===============================
require("./auth2fa").install(app);

const {
    requireAuth,
} = require("./auth/middleware");

const {
    tmsFetch,
    tmsOrderFetch,
} = require("./auth/reelTms");

const {
    revokeSession,
    revokeAllUserSessions,
    clearSessionCookie,
} = require("./auth/session");

const {
    writeSecurityEvent,
} = require("./auth/audit");


app.get(
    "/api/auth/session",
    requireAuth,
    async (req, res) => {
        try {
            const userKey =
                String(req.auth.userKey);

            const rows =
                await supabaseRequest(
                    `Login?id=eq.${encodeURIComponent(userKey)}` +
                    `&select=id,kullanici_adi,kullanici,rol,allowedScreens,allowedButtons` +
                    `&limit=1`
                );

            const row =
                Array.isArray(rows) && rows.length
                    ? rows[0]
                    : null;

            if (!row) {
                return res.status(401).json({
                    ok: false,
                    authenticated: false,
                    error: "Oturum kullanicisi bulunamadi.",
                });
            }

            const parseArray = (value) => {
                if (Array.isArray(value)) {
                    return value;
                }

                if (
                    value === null ||
                    value === undefined ||
                    value === ""
                ) {
                    return [];
                }

                if (typeof value === "string") {
                    try {
                        const parsed =
                            JSON.parse(value);

                        return Array.isArray(parsed)
                            ? parsed
                            : [];
                    } catch {
                        return [];
                    }
                }

                return [];
            };

            const user = {
                id:
                    row.id,

                kullanici_adi:
                    row.kullanici_adi || "",

                kullanici:
                    row.kullanici || "",

                rol:
                    row.rol || "kullanici",

                allowedScreens:
                    parseArray(
                        row.allowedScreens
                    ),

                allowedButtons:
                    parseArray(
                        row.allowedButtons
                    ),
            };

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.json({
                ok: true,
                authenticated: true,
                userKey,
                user,
            });
        } catch (error) {
            console.error(
                "[AUTH SESSION]",
                error?.message
            );

            return res.status(500).json({
                ok: false,
                authenticated: false,
                error:
                    "Oturum bilgisi alinamadi.",
            });
        }
    }
);


app.post(
    "/api/auth/logout",
    requireAuth,
    async (req, res) => {
        try {
            await revokeSession(
                req.auth.sessionId,
                "logout"
            );

            clearSessionCookie(res);

            await writeSecurityEvent({
                req,
                userKey: req.auth.userKey,
                eventType: "LOGOUT",
                success: true,
            });

            return res.json({
                ok: true,
            });
        } catch (error) {
            console.error(
                "[LOGOUT]",
                error?.message
            );

            return res.status(500).json({
                error:
                    "Cikis islemi tamamlanamadi.",
            });
        }
    }
);


app.post(
    "/api/auth/logout-all",
    requireAuth,
    async (req, res) => {
        try {
            await revokeAllUserSessions(
                req.auth.userKey,
                "logout_all"
            );

            clearSessionCookie(res);

            await writeSecurityEvent({
                req,
                userKey: req.auth.userKey,
                eventType: "LOGOUT_ALL",
                success: true,
            });

            return res.json({
                ok: true,
            });
        } catch (error) {
            console.error(
                "[LOGOUT ALL]",
                error?.message
            );

            return res.status(500).json({
                error:
                    "Tum oturumlar kapatilamadi.",
            });
        }
    }
);

const PORT = process.env.PORT || 5000;
console.log(`ğŸ” Supabase env: URL=${Boolean(process.env.SUPABASE_URL)} KEY=${Boolean(process.env.SUPABASE_SERVICE_ROLE_KEY)}`);

app.post(
    "/api/reel-api/tmsdespatchincomeexpenses/addexpense",
    requireAuth,
    async (req, res) => {
        try {
            const upstream = await tmsFetch(
                req.auth.userKey,
                "/api/tmsdespatchincomeexpenses/addexpense",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(req.body ?? {}),
                }
            );

            const text = await upstream.text();

            res
                .status(upstream.status)
                .type(
                    upstream.headers.get("content-type") ||
                    "application/json"
                )
                .send(text);
        } catch (err) {
            console.error(
                "TMS addexpense proxy error:",
                err?.message || "Unknown error"
            );

            res
                .status(err?.status || 502)
                .json({
                    error: "TMS istegi tamamlanamadi.",
                });
        }
    }
);

// ===============================
// 2) TMS PROD / ADD INCOME
// ===============================
app.post(
    "/api/reel-api/tmsdespatchincomeexpenses/addincome",
    requireAuth,
    async (req, res) => {
        try {
            const upstream = await tmsFetch(
                req.auth.userKey,
                "/api/tmsdespatchincomeexpenses/addincome",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(req.body ?? {}),
                }
            );

            const text = await upstream.text();

            res
                .status(upstream.status)
                .type(
                    upstream.headers.get("content-type") ||
                    "application/json"
                )
                .send(text);
        } catch (err) {
            console.error(
                "TMS addincome proxy error:",
                err?.message || "Unknown error"
            );

            res
                .status(err?.status || 502)
                .json({
                    error: "TMS istegi tamamlanamadi.",
                });
        }
    }
);

// ===============================
// 3) TMS PROD / ADD ORDER  âœ… YENÄ°
// ===============================
// ===============================
// TMS TEST / ADD EXPENSE
// ===============================
app.post(
    "/api/reel-api/tmsdespatchincomeexpenses/test/testaddexpense",
    requireAuth,
    async (req, res) => {
        try {
            const upstream = await tmsFetch(
                req.auth.userKey,
                "/api/tmsdespatchincomeexpenses/test/testaddexpense",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(req.body ?? {}),
                },
                {
                    environment: "test",
                }
            );

            const text = await upstream.text();

            res
                .status(upstream.status)
                .type(
                    upstream.headers.get("content-type") ||
                    "application/json"
                )
                .send(text);
        } catch (err) {
            console.error(
                "TEST TMS addexpense proxy error:",
                err?.message || "Unknown error"
            );

            res
                .status(err?.status || 502)
                .json({
                    error: "TEST TMS istegi tamamlanamadi.",
                });
        }
    }
);

// ===============================
// TMS TEST / ADD INCOME
// ===============================
app.post(
    "/api/reel-api/tmsdespatchincomeexpenses/test/testaddincome",
    requireAuth,
    async (req, res) => {
        try {
            const upstream = await tmsFetch(
                req.auth.userKey,
                "/api/tmsdespatchincomeexpenses/test/testaddincome",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(req.body ?? {}),
                },
                {
                    environment: "test",
                }
            );

            const text = await upstream.text();

            res
                .status(upstream.status)
                .type(
                    upstream.headers.get("content-type") ||
                    "application/json"
                )
                .send(text);
        } catch (err) {
            console.error(
                "TEST TMS addincome proxy error:",
                err?.message || "Unknown error"
            );

            res
                .status(err?.status || 502)
                .json({
                    error: "TEST TMS istegi tamamlanamadi.",
                });
        }
    }
);
app.post(
    "/api/reel-api/tmsorders/add",
    requireAuth,
    async (req, res) => {
        try {
            const hasOrderServiceAccount =
                Boolean(
                    String(
                        process.env.TMS_ORDER_USERNAME || ""
                    ).trim()
                ) &&
                Boolean(
                    String(
                        process.env.TMS_ORDER_PASSWORD || ""
                    )
                );

            const upstream =
                hasOrderServiceAccount
                    ? await tmsOrderFetch(
                        "/api/tmsorders/add",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(req.body ?? {}),
                        }
                    )
                    : await tmsFetch(
                        req.auth.userKey,
                        "/api/tmsorders/add",
                        {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json",
                            },
                            body: JSON.stringify(req.body ?? {}),
                        }
                    );

            const text = await upstream.text();

            res
                .status(upstream.status)
                .type(
                    upstream.headers.get("content-type") ||
                    "application/json"
                )
                .send(text);
        } catch (err) {
            console.error(
                "TMS addorder proxy error:",
                err?.message || "Unknown error"
            );

            res
                .status(err?.status || 502)
                .json({
                    error: "TMS istegi tamamlanamadi.",
                });
        }
    }
);


// ===============================
// TMS ORDERS / GET ALL - PRICING
// ===============================
app.post(
    "/api/fiyatlandirma/tmsorders/getall",
    requireAuth,
    async (req, res) => {
        try {
            const odakApiKey =
                process.env.ODAK_API_KEY;

            if (!odakApiKey) {
                return res.status(500).json({
                    error: "Sunucu API yapilandirmasi eksik.",
                });
            }

            const upstream = await fetch(
                "https://api.odaklojistik.com.tr/api/tmsorders/getall",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        Accept: "application/json",
                        Authorization: odakApiKey,
                    },
                    body: JSON.stringify({
                        startDate: req.body?.startDate,
                        endDate: req.body?.endDate,
                        userId: 1,
                    }),
                }
            );

            const text = await upstream.text();

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res
                .status(upstream.status)
                .type(
                    upstream.headers.get("content-type") ||
                    "application/json"
                )
                .send(text);
        } catch (err) {
            console.error(
                "Pricing TMS GetAll error:",
                err?.message || "Unknown error"
            );

            return res.status(502).json({
                error: "TMS siparis verisi alinamadi.",
            });
        }
    }
);
// ===============================
// 5) PETROL OFISI / FUEL PRICE CHECK
// ===============================
const trAscii = (value = "") => String(value)
    .trim()
    .toLocaleUpperCase("tr-TR")
    .replace(/Ä°/g, "I").replace(/IÌ‡/g, "I")
    .replace(/Å/g, "S").replace(/Ä/g, "G")
    .replace(/Ãœ/g, "U").replace(/Ã–/g, "O").replace(/Ã‡/g, "C")
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "");

const citySlug = (value = "") => trAscii(value)
    .toLocaleLowerCase("en-US")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

const decodeHtml = (value = "") => String(value)
    .replace(/&nbsp;|&#160;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&ccedil;/gi, "Ã§").replace(/&Ccedil;/gi, "Ã‡")
    .replace(/&ouml;/gi, "Ã¶").replace(/&Ouml;/gi, "Ã–")
    .replace(/&uuml;/gi, "Ã¼").replace(/&Uuml;/gi, "Ãœ")
    .replace(/&#287;/g, "ÄŸ").replace(/&#286;/g, "Ä")
    .replace(/&#351;/g, "ÅŸ").replace(/&#350;/g, "Å")
    .replace(/&#305;/g, "Ä±").replace(/&#304;/g, "Ä°");

const textOnly = (html = "") => decodeHtml(html)
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();

const firstPrice = (value = "") => {
    const m = String(value).match(/(\d{1,3}(?:[.,]\d{1,2}))/);
    return m ? Number(m[1].replace(",", ".")) : NaN;
};

function parsePetrolOfisiPrice(html, district, fuel, city = "", vatIncluded = true) {
    const wantedDistrict = trAscii(district);
    // Petrol Ofisi bazÄ± illerde merkez satÄ±rÄ±nÄ± "MERKEZ" yerine doÄŸrudan il adÄ±yla yayÄ±mlÄ±yor.
    // Ã–rn: EskiÅŸehir merkez = ESKISEHIR, Adana merkez = ADANA.
    const acceptedDistricts = new Set([wantedDistrict]);
    if (wantedDistrict === "MERKEZ" && city) acceptedDistricts.add(trAscii(city));
    const rows = [...html.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)];
    for (const row of rows) {
        const cells = [...row[1].matchAll(/<t[dh]\b[^>]*>([\s\S]*?)<\/t[dh]>/gi)].map(m => textOnly(m[1]));
        if (cells.length < 4 || !acceptedDistricts.has(trAscii(cells[0]))) continue;
        const index = fuel === "Benzin" ? 1 : fuel === "Motorin" ? 2 : fuel === "LPG" ? 6 : -1;
        if (index < 0 || !cells[index]) throw new Error(`Desteklenmeyen yakÄ±t tÃ¼rÃ¼: ${fuel}`);
        const matches = String(cells[index]).match(/\d{1,3}(?:[.,]\d{1,2})/g) || [];
        // Petrol Ofisi hÃ¼cresinde ilk deÄŸer KDV dahil, ikinci deÄŸer +KDV (KDV hariÃ§) olarak yayÄ±nlanÄ±r.
        // BÄ°M sÃ¶zleÅŸmesi iÃ§in "KDV dahil fiyatlar gÃ¶sterilsin" kapalÄ± olduÄŸundan ikinci deÄŸer kullanÄ±lÄ±r.
        const grossRaw = matches[0];
        const grossPrice = grossRaw ? Number(grossRaw.replace(",", ".")) : NaN;
        // KDV kapalÄ± gÃ¶rÃ¼nÃ¼mde PO'nun +KDV (net) deÄŸeri kullanÄ±lÄ±r. BazÄ± upstream HTML
        // cevaplarÄ±nda ikinci deÄŸer gizli/dinamik geldiÄŸi iÃ§in tek deÄŸer gÃ¶rÃ¼lÃ¼rse brÃ¼t fiyatÄ±
        // %20 KDV'den arÄ±ndÄ±rÄ±p PO ekranÄ±ndaki kuruÅŸ yukarÄ± yuvarlama davranÄ±ÅŸÄ±yla Ã¼retiriz.
        const netFromGross = Number.isFinite(grossPrice) ? Math.ceil((grossPrice / 1.20) * 100 - 1e-9) / 100 : NaN;
        const raw = (!vatIncluded && matches.length > 1) ? matches[matches.length - 1] : grossRaw;
        const parsed = raw ? Number(raw.replace(",", ".")) : NaN;
        const price = !vatIncluded && matches.length === 1 ? netFromGross : parsed;
        if (!Number.isFinite(price)) throw new Error(`${district} iÃ§in ${fuel} fiyatÄ± ayrÄ±ÅŸtÄ±rÄ±lamadÄ±.`);
        return price;
    }
    throw new Error(`${district} ilÃ§esi Petrol Ofisi fiyat tablosunda bulunamadÄ±.`);
}

function shellProductCode(data, fuel) {
    const products = Array.isArray(data?.products) ? data.products : [];
    const wanted = fuel === "Motorin" ? ["vp diesel", "v-power diesel", "motorin", "diesel"]
        : fuel === "Benzin" ? ["v-power", "k.benzin", "benzin", "95 oktan"]
        : ["lpg", "autogas", "otogaz"];

    const product = products.find((p) => {
        const text = trAscii(`${p?.fepProductName || ""} ${p?.webProductName || ""} ${p?.genProductName || ""}`);
        return wanted.some((name) => text.includes(trAscii(name)));
    });
    if (!product?.fepProductCode) {
        throw new Error(`Shell Ã¼rÃ¼n kodu bulunamadÄ±: ${fuel}`);
    }
    return String(product.fepProductCode);
}

function parseShellApiPrice(data, city, district, fuel) {
    const groups = Array.isArray(data?.groups) ? data.groups : [];
    const wantedCity = trAscii(city);
    const wantedDistrict = trAscii(district);
    const cityNode = groups.find((g) => trAscii(g?.cityName || "") === wantedCity);
    if (!cityNode) throw new Error(`Shell resmi API yanÄ±tÄ±nda ${city} ili bulunamadÄ±.`);

    const counties = Array.isArray(cityNode.counties) ? cityNode.counties : [];
    const county = counties.find((c) => trAscii(c?.countyName || "") === wantedDistrict);
    if (!county) throw new Error(`Shell resmi API yanÄ±tÄ±nda ${city} / ${district} ilÃ§esi bulunamadÄ±.`);

    const productCode = shellProductCode(data, fuel);
    const prices = county.prices || {};
    let rawPrice = prices[productCode];
    if (rawPrice == null) {
        const normalizedCode = productCode.trim();
        const key = Object.keys(prices).find((k) => String(k).trim() === normalizedCode);
        if (key) rawPrice = prices[key];
    }
    const price = Number(rawPrice);
    if (!Number.isFinite(price)) {
        throw new Error(`Shell resmi API yanÄ±tÄ±nda ${city} / ${district} / ${fuel} fiyatÄ± bulunamadÄ±.`);
    }
    return price;
}

async function fetchShellPrice(city, district, fuel) {
    const url = "https://pompafiyat.turkiyeshell.com/api/Public/prices";
    const upstream = await fetch(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/153 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.7",
            "Referer": "https://pompafiyat.turkiyeshell.com/prices",
            "Origin": "https://pompafiyat.turkiyeshell.com"
        },
        redirect: "follow"
    });
    const raw = await upstream.text();
    if (!upstream.ok) throw new Error(`Shell resmi fiyat API'si HTTP ${upstream.status} dÃ¶ndÃ¼rdÃ¼.`);
    let data;
    try { data = JSON.parse(raw); }
    catch (_) { throw new Error("Shell resmi fiyat API'si JSON dÃ¶ndÃ¼rmedi."); }
    const price = parseShellApiPrice(data, city, district, fuel);
    return { price, sourceUrl: url };
}

app.get("/api/fuel-check", async (req, res) => {
    res.set("Cache-Control", "no-store");
    try {
        const provider = String(req.query.provider || "");
        const city = String(req.query.city || "").trim();
        const district = String(req.query.district || "").trim();
        const fuel = String(req.query.fuel || "Motorin").trim();
        const vatIncluded = String(req.query.vatIncluded ?? "true").toLowerCase() !== "false";
        if (!city || !district) return res.status(400).json({ ok: false, error: "Ä°l ve ilÃ§e zorunludur." });

        let sourceUrl, price, providerName, sourceLabel;
        if (provider === "petrol-ofisi") {
            const slug = citySlug(city);
            sourceUrl = `https://www.petrolofisi.com.tr/akaryakit-fiyatlari/${slug}-akaryakit-fiyatlari`;
            providerName = "Petrol Ofisi";
            sourceLabel = "Petrol Ofisi resmi fiyat sayfasÄ±";
        } else if (provider === "shell") {
            sourceUrl = "https://www.shell.com.tr/suruculer/shell-yakitlari/akaryakit-pompa-satis-fiyatlari.html";
            providerName = "Shell";
            sourceLabel = "Shell resmi pompa fiyat API'si";
        } else {
            return res.status(400).json({ ok: false, error: "Bilinmeyen akaryakÄ±t saÄŸlayÄ±cÄ±sÄ±." });
        }

        if (provider === "shell") {
            const shellResult = await fetchShellPrice(city, district, fuel);
            price = shellResult.price;
            sourceUrl = shellResult.sourceUrl;
        } else {
            const upstream = await fetch(sourceUrl, {
                headers: {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.7",
                },
                redirect: "follow",
            });
            const html = await upstream.text();
            if (!upstream.ok) throw new Error(`${providerName} fiyat sayfasÄ± HTTP ${upstream.status} dÃ¶ndÃ¼rdÃ¼.`);
            price = parsePetrolOfisiPrice(html, district, fuel, city, vatIncluded);
        }
        return res.json({ ok: true, provider: providerName, city, district, fuel, price, vatIncluded: provider === "petrol-ofisi" ? vatIncluded : null, priceMode: provider === "petrol-ofisi" ? (vatIncluded ? "KDV dahil" : "KDV hariÃ§ (+KDV)") : "Pompa fiyatÄ±", sourceUrl, sourceLabel, checkedAt: new Date().toISOString() });
    } catch (err) {
        console.error("[fuel-check]", err);
        return res.status(502).json({ ok: false, error: err.message || "Fiyat kontrolÃ¼ baÅŸarÄ±sÄ±z." });
    }
});


// ===============================
// FUEL SERVICE â€” Render live backend
// ===============================
const fuelText = (html = "") => String(html)
  .replace(/&nbsp;|&#160;/gi, " ").replace(/&amp;/gi, "&")
  .replace(/<script[\s\S]*?<\/script>/gi, " ")
  .replace(/<style[\s\S]*?<\/style>/gi, " ")
  .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();

const fuelAscii = (value = "") => String(value).trim().toLocaleUpperCase("tr-TR")
  .replace(/Ä°/g, "I").replace(/Å/g, "S").replace(/Ä/g, "G")
  .replace(/Ãœ/g, "U").replace(/Ã–/g, "O").replace(/Ã‡/g, "C")
  .normalize("NFD").replace(/[\u0300-\u036f]/g, "");

const fuelSlug = (value = "") => fuelAscii(value).toLowerCase()
  .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

function parsePetrolOfisi(html, city, district, fuel, vatIncluded) {
  const accepted = new Set([fuelAscii(district)]);
  if (fuelAscii(district) === "MERKEZ") accepted.add(fuelAscii(city));
  const rows = [...html.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)];

  for (const row of rows) {
    const cells = [...row[1].matchAll(/<t[dh]\b[^>]*>([\s\S]*?)<\/t[dh]>/gi)]
      .map(m => fuelText(m[1]));
    if (cells.length < 3 || !accepted.has(fuelAscii(cells[0]))) continue;

    const idx = fuel === "Benzin" ? 1 : fuel === "Motorin" ? 2 : fuel === "LPG" ? 6 : -1;
    if (idx < 0 || !cells[idx]) continue;

    const nums = String(cells[idx]).match(/\d{1,3}(?:[.,]\d{1,2})/g) || [];
    const gross = nums[0] ? Number(nums[0].replace(",", ".")) : NaN;
    let price = gross;

    if (!vatIncluded && nums.length > 1)
      price = Number(nums[nums.length - 1].replace(",", "."));
    else if (!vatIncluded && Number.isFinite(gross))
      price = Math.ceil((gross / 1.20) * 100 - 1e-9) / 100;

    if (Number.isFinite(price)) return price;
  }
  throw new Error(`Petrol Ofisi fiyatÄ± bulunamadÄ±: ${city}/${district} ${fuel}`);
}

function shellProductCode(data, fuel) {
  const wanted = fuel === "Motorin"
    ? ["VP DIESEL","V-POWER DIESEL","MOTORIN","DIESEL"]
    : fuel === "Benzin" ? ["V-POWER","BENZIN","95 OKTAN"] : ["LPG","AUTOGAS","OTOGAZ"];

  const products = Array.isArray(data?.products) ? data.products : [];
  const product = products.find(item =>
    wanted.some(name =>
      fuelAscii(`${item?.fepProductName || ""} ${item?.webProductName || ""} ${item?.genProductName || ""}`)
        .includes(fuelAscii(name))
    )
  );
  if (!product?.fepProductCode) throw new Error("Shell Ã¼rÃ¼n kodu bulunamadÄ±.");
  return String(product.fepProductCode);
}

function parseShell(data, city, district, fuel) {
  const cityNode = (Array.isArray(data?.groups) ? data.groups : [])
    .find(item => fuelAscii(item?.cityName || "") === fuelAscii(city));
  if (!cityNode) throw new Error(`Shell il bulunamadÄ±: ${city}`);

  const county = (Array.isArray(cityNode.counties) ? cityNode.counties : [])
    .find(item => fuelAscii(item?.countyName || "") === fuelAscii(district));
  if (!county) throw new Error(`Shell ilÃ§e bulunamadÄ±: ${city}/${district}`);

  const code = shellProductCode(data, fuel);
  const prices = county.prices || {};
  const key = Object.keys(prices).find(k => String(k).trim() === code.trim());
  const price = Number(prices[code] ?? (key ? prices[key] : undefined));

  if (!Number.isFinite(price)) throw new Error("Shell fiyatÄ± bulunamadÄ±.");
  return price;
}

async function fetchFuelPrice({ provider, city, district, fuel = "Motorin", vatIncluded = true }) {
  if (provider === "shell") {
    const sourceUrl = "https://pompafiyat.turkiyeshell.com/api/Public/prices";
    const upstream = await fetch(sourceUrl, {
      headers: { "User-Agent": "Mozilla/5.0", Accept: "application/json, text/plain, */*" }
    });
    const raw = await upstream.text();
    if (!upstream.ok) throw new Error(`Shell HTTP ${upstream.status}`);
    let data;
    try { data = JSON.parse(raw); }
    catch { throw new Error("Shell servisi JSON dÃ¶ndÃ¼rmedi."); }
    return { price: parseShell(data, city, district, fuel), sourceUrl, providerName: "Shell" };
  }

  const sourceUrl =
    `https://www.petrolofisi.com.tr/akaryakit-fiyatlari/${fuelSlug(city)}-akaryakit-fiyatlari`;
  const upstream = await fetch(sourceUrl, {
    headers: {
      "User-Agent": "Mozilla/5.0",
      Accept: "text/html",
      "Accept-Language": "tr-TR,tr;q=0.9"
    },
    redirect: "follow"
  });
  const html = await upstream.text();
  if (!upstream.ok) throw new Error(`Petrol Ofisi HTTP ${upstream.status}`);
  return {
    price: parsePetrolOfisi(html, city, district, fuel, vatIncluded),
    sourceUrl,
    providerName: "Petrol Ofisi"
  };
}

const fuelTargets = [
  { customer:"BÄ°M", provider:"petrol-ofisi", city:"Ä°stanbul", district:"SANCAKTEPE", fuel:"Motorin", vatIncluded:false },
  { customer:"TEVERPAN", provider:"petrol-ofisi", city:"TekirdaÄŸ", district:"Ã‡ERKEZKÃ–Y", fuel:"Motorin", vatIncluded:true },
  { customer:"EFOR Ã‡AY", provider:"petrol-ofisi", city:"Tokat", district:"ERBAA", fuel:"Motorin", vatIncluded:true },
  { customer:"CORTEVA", provider:"petrol-ofisi", city:"Adana", district:"MERKEZ", fuel:"Motorin", vatIncluded:true },
  { customer:"CMC AGRO", provider:"petrol-ofisi", city:"Bursa", district:"KARACABEY", fuel:"Motorin", vatIncluded:true },
  { customer:"ETÄ°", provider:"petrol-ofisi", city:"EskiÅŸehir", district:"ODUNPAZARI", fuel:"Motorin", vatIncluded:true },
  { customer:"KWS", provider:"petrol-ofisi", city:"EskiÅŸehir", district:"MERKEZ", fuel:"Motorin", vatIncluded:true },
  { customer:"FASDAT", provider:"shell", city:"Afyon", district:"MERKEZ", fuel:"Motorin", vatIncluded:true }
];

let fuelState = { running:false, lastRun:null, trigger:null, results:[] };

async function refreshFuelPrices(trigger = "scheduled") {
  if (fuelState.running) return fuelState;
  fuelState.running = true;
  const results = [];

  for (const target of fuelTargets) {
    try {
      const result = await fetchFuelPrice(target);
      results.push({ ...target, ok:true, price:result.price, checkedAt:new Date().toISOString() });
    } catch (error) {
      results.push({ ...target, ok:false, error:error.message, checkedAt:new Date().toISOString() });
    }
  }

  fuelState = { running:false, lastRun:new Date().toISOString(), trigger, results };
  return fuelState;
}

app.get("/api/fuel-automation/status",
  (req,res) => res.json({ ok:true, ...fuelState }));

app.get("/api/fuel-automation/live", async (req,res) => {
  try { res.json({ ok:true, ...(await refreshFuelPrices("live")) }); }
  catch (error) { res.status(500).json({ ok:false, error:error.message }); }
});

app.post("/api/fuel-automation/run", async (req,res) => {
  try { res.json({ ok:true, ...(await refreshFuelPrices("manual")) }); }
  catch (error) { res.status(500).json({ ok:false, error:error.message }); }
});

app.get("/health", (req,res) => res.json({
  ok:true,
  service:"tedarik_analiz_backend",
  fuelAutomation:true,
  time:new Date().toISOString()
}));

setTimeout(() => refreshFuelPrices("startup").catch(console.error), 10000);
setInterval(() => refreshFuelPrices("scheduled").catch(console.error), 5 * 60 * 1000);


/*
 * Secure admin user management.
 * Authentication + admin authorization
 * router seviyesinde uygulanir.
 */
app.use("/api/data", dataApiRouter);
app.use("/api/admin/users", adminUsersRouter);
// CENTRAL_ERROR_HANDLER_V1
app.use((err, req, res, next) => {
  const isJsonParseError =
    err?.type === "entity.parse.failed" ||
    (
      err instanceof SyntaxError &&
      err?.status === 400 &&
      Object.prototype.hasOwnProperty.call(err, "body")
    );

  if (isJsonParseError) {
    return res.status(400).json({
      error: "Gecersiz JSON govdesi."
    });
  }

  console.error("[UNHANDLED_ERROR]", {
    method: req.method,
    path: req.originalUrl,
    name: err?.name || "Error",
    message: err?.message || "Unknown error"
  });

  if (res.headersSent) {
    return next(err);
  }

  return res.status(500).json({
    error: "Sunucu hatasi."
  });
});
app.listen(PORT, () => {
  console.log(`Backend Ã§alÄ±ÅŸÄ±yor: port ${PORT} | fuel-check aktif | 5 dk yakÄ±t kontrolÃ¼ aktif`);
});
