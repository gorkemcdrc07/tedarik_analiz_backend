const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const { createClient } = require("@supabase/supabase-js");
const { createSession } = require("./auth/session");
const { requireAuth } = require("./auth/middleware");
const { getTmsToken } = require("./auth/reelTms");
// .env dosyasını process.cwd() yerine doğrudan server klasöründen yükle.
// Böylece `npm --prefix server start` ve farklı çalışma dizinlerinde aynı davranır.
const envPath = path.resolve(__dirname, ".env");
require("dotenv").config({ path: envPath, override: true });

const app = express();

app.set("trust proxy", 1);

const allowedOrigins = new Set([
    "https://tedarik-analiz.vercel.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]);

app.use(
    cors({
        origin(origin, callback) {
            if (!origin || allowedOrigins.has(origin)) {
                return callback(null, true);
            }

            return callback(new Error("CORS origin not allowed."));
        },
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);

app.use(cookieParser());
app.use(express.json());

const PORT = process.env.PORT || 5000;
console.log(`🔐 Supabase env: URL=${Boolean(process.env.SUPABASE_URL)} KEY=${Boolean(process.env.SUPABASE_SERVICE_ROLE_KEY)}`);

// ===============================
// UYGULAMA LOGIN / SUPABASE
// ===============================

const supabase =
    process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY
        ? createClient(
            process.env.SUPABASE_URL,
            process.env.SUPABASE_SERVICE_ROLE_KEY,
            {
                auth: {
                    persistSession: false,
                    autoRefreshToken: false
                }
            }
        )
        : null;

app.post("/api/auth/login", async (req, res) => {
    try {
        if (!supabase) {
            console.error("Supabase environment variables missing.");

            return res.status(503).json({
                ok: false,
                error: "Kimlik do?rulama servisi kullan?lam?yor."
            });
        }

        const username = String(req.body?.username || "").trim();
        const password = String(req.body?.password || "");

        if (!username || !password) {
            return res.status(400).json({
                ok: false,
                error: "Kullan?c? ad? ve ?ifre zorunludur."
            });
        }

        const { data: user, error } = await supabase
            .from("Login")
            .select(
                'id,kullanici_adi,kullanici,"Reel_kullanici",rol,"allowedScreens","allowedButtons",password_hash'
            )
            .eq("kullanici_adi", username)
            .maybeSingle();

        if (error) {
            console.error("Supabase login error:", error.message);

            return res.status(500).json({
                ok: false,
                error: "Giri? s?ras?nda veritaban? hatas? olu?tu."
            });
        }

        if (!user || !user.password_hash) {
            return res.status(401).json({
                ok: false,
                error: "Kullan?c? ad? veya ?ifre hatal?."
            });
        }

        const passwordMatches = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatches) {
            return res.status(401).json({
                ok: false,
                error: "Kullan?c? ad? veya ?ifre hatal?."
            });
        }

        const { password_hash, ...safeUser } = user;

        await createSession({
            req,
            res,
            userKey: user.id,
        });

        return res.json({
            ok: true,
            user: safeUser
        });

    } catch (err) {
        console.error("Application login error:", err);

        return res.status(500).json({
            ok: false,
            error: "Giri? i?lemi tamamlanamad?."
        });
    }
});

// ===============================
// 1) TMS PROD / ADD EXPENSE
// ===============================
app.post("/api/reel-api/tmsdespatchincomeexpenses/addexpense", async (req, res) => {
    try {
        const upstream = await fetch(
            "https://tms.odaklojistik.com.tr/api/tmsdespatchincomeexpenses/addexpense",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: req.headers.authorization || "",
                },
                body: JSON.stringify(req.body),
            }
        );

        const text = await upstream.text();
        res.status(upstream.status).send(text);
    } catch (err) {
        res.status(500).json({ error: "Proxy error", detail: err.message });
    }
});

// ===============================
// 2) TMS PROD / ADD INCOME
// ===============================
app.post("/api/reel-api/tmsdespatchincomeexpenses/addincome", async (req, res) => {
    try {
        const upstream = await fetch(
            "https://tms.odaklojistik.com.tr/api/tmsdespatchincomeexpenses/addincome",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: req.headers.authorization || "",
                },
                body: JSON.stringify(req.body),
            }
        );

        const text = await upstream.text();
        res.status(upstream.status).send(text);
    } catch (err) {
        res.status(500).json({ error: "Proxy error", detail: err.message });
    }
});

// ===============================
// 3) TMS PROD / ADD ORDER  ✅ YENİ
// ===============================
app.post("/api/reel-api/tmsorders/add", async (req, res) => {
    try {
        const upstream = await fetch(
            "https://tms.odaklojistik.com.tr/api/tmsorders/add",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: req.headers.authorization || "",
                },
                body: JSON.stringify(req.body),
            }
        );

        const text = await upstream.text();
        res.status(upstream.status).send(text);
    } catch (err) {
        res.status(500).json({ error: "Order proxy error", detail: err.message });
    }
});

// ===============================
// 4) TMS AUTH LOGIN (PROD)
// ===============================
app.post(
    "/reel-auth/api/auth/login",
    requireAuth,
    async (req, res) => {
        try {
            const token = await getTmsToken(
                req.auth.userKey,
                "prod"
            );

            return res.json({
                token,
            });
        } catch (err) {
            console.error(
                "Secure TMS token error:",
                err?.message || err
            );

            return res.status(502).json({
                error: "TMS token alinamadi.",
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
    .replace(/İ/g, "I").replace(/İ/g, "I")
    .replace(/Ş/g, "S").replace(/Ğ/g, "G")
    .replace(/Ü/g, "U").replace(/Ö/g, "O").replace(/Ç/g, "C")
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
    .replace(/&ccedil;/gi, "ç").replace(/&Ccedil;/gi, "Ç")
    .replace(/&ouml;/gi, "ö").replace(/&Ouml;/gi, "Ö")
    .replace(/&uuml;/gi, "ü").replace(/&Uuml;/gi, "Ü")
    .replace(/&#287;/g, "ğ").replace(/&#286;/g, "Ğ")
    .replace(/&#351;/g, "ş").replace(/&#350;/g, "Ş")
    .replace(/&#305;/g, "ı").replace(/&#304;/g, "İ");

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
    // Petrol Ofisi bazı illerde merkez satırını "MERKEZ" yerine doğrudan il adıyla yayımlıyor.
    // Örn: Eskişehir merkez = ESKISEHIR, Adana merkez = ADANA.
    const acceptedDistricts = new Set([wantedDistrict]);
    if (wantedDistrict === "MERKEZ" && city) acceptedDistricts.add(trAscii(city));
    const rows = [...html.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)];
    for (const row of rows) {
        const cells = [...row[1].matchAll(/<t[dh]\b[^>]*>([\s\S]*?)<\/t[dh]>/gi)].map(m => textOnly(m[1]));
        if (cells.length < 4 || !acceptedDistricts.has(trAscii(cells[0]))) continue;
        const index = fuel === "Benzin" ? 1 : fuel === "Motorin" ? 2 : fuel === "LPG" ? 6 : -1;
        if (index < 0 || !cells[index]) throw new Error(`Desteklenmeyen yakıt türü: ${fuel}`);
        const matches = String(cells[index]).match(/\d{1,3}(?:[.,]\d{1,2})/g) || [];
        // Petrol Ofisi hücresinde ilk değer KDV dahil, ikinci değer +KDV (KDV hariç) olarak yayınlanır.
        // BİM sözleşmesi için "KDV dahil fiyatlar gösterilsin" kapalı olduğundan ikinci değer kullanılır.
        const grossRaw = matches[0];
        const grossPrice = grossRaw ? Number(grossRaw.replace(",", ".")) : NaN;
        // KDV kapalı görünümde PO'nun +KDV (net) değeri kullanılır. Bazı upstream HTML
        // cevaplarında ikinci değer gizli/dinamik geldiği için tek değer görülürse brüt fiyatı
        // %20 KDV'den arındırıp PO ekranındaki kuruş yukarı yuvarlama davranışıyla üretiriz.
        const netFromGross = Number.isFinite(grossPrice) ? Math.ceil((grossPrice / 1.20) * 100 - 1e-9) / 100 : NaN;
        const raw = (!vatIncluded && matches.length > 1) ? matches[matches.length - 1] : grossRaw;
        const parsed = raw ? Number(raw.replace(",", ".")) : NaN;
        const price = !vatIncluded && matches.length === 1 ? netFromGross : parsed;
        if (!Number.isFinite(price)) throw new Error(`${district} için ${fuel} fiyatı ayrıştırılamadı.`);
        return price;
    }
    throw new Error(`${district} ilçesi Petrol Ofisi fiyat tablosunda bulunamadı.`);
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
        throw new Error(`Shell ürün kodu bulunamadı: ${fuel}`);
    }
    return String(product.fepProductCode);
}

function parseShellApiPrice(data, city, district, fuel) {
    const groups = Array.isArray(data?.groups) ? data.groups : [];
    const wantedCity = trAscii(city);
    const wantedDistrict = trAscii(district);
    const cityNode = groups.find((g) => trAscii(g?.cityName || "") === wantedCity);
    if (!cityNode) throw new Error(`Shell resmi API yanıtında ${city} ili bulunamadı.`);

    const counties = Array.isArray(cityNode.counties) ? cityNode.counties : [];
    const county = counties.find((c) => trAscii(c?.countyName || "") === wantedDistrict);
    if (!county) throw new Error(`Shell resmi API yanıtında ${city} / ${district} ilçesi bulunamadı.`);

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
        throw new Error(`Shell resmi API yanıtında ${city} / ${district} / ${fuel} fiyatı bulunamadı.`);
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
    if (!upstream.ok) throw new Error(`Shell resmi fiyat API'si HTTP ${upstream.status} döndürdü.`);
    let data;
    try { data = JSON.parse(raw); }
    catch (_) { throw new Error("Shell resmi fiyat API'si JSON döndürmedi."); }
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
        if (!city || !district) return res.status(400).json({ ok: false, error: "İl ve ilçe zorunludur." });

        let sourceUrl, price, providerName, sourceLabel;
        if (provider === "petrol-ofisi") {
            const slug = citySlug(city);
            sourceUrl = `https://www.petrolofisi.com.tr/akaryakit-fiyatlari/${slug}-akaryakit-fiyatlari`;
            providerName = "Petrol Ofisi";
            sourceLabel = "Petrol Ofisi resmi fiyat sayfası";
        } else if (provider === "shell") {
            sourceUrl = "https://www.shell.com.tr/suruculer/shell-yakitlari/akaryakit-pompa-satis-fiyatlari.html";
            providerName = "Shell";
            sourceLabel = "Shell resmi pompa fiyat API'si";
        } else {
            return res.status(400).json({ ok: false, error: "Bilinmeyen akaryakıt sağlayıcısı." });
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
            if (!upstream.ok) throw new Error(`${providerName} fiyat sayfası HTTP ${upstream.status} döndürdü.`);
            price = parsePetrolOfisiPrice(html, district, fuel, city, vatIncluded);
        }
        return res.json({ ok: true, provider: providerName, city, district, fuel, price, vatIncluded: provider === "petrol-ofisi" ? vatIncluded : null, priceMode: provider === "petrol-ofisi" ? (vatIncluded ? "KDV dahil" : "KDV hariç (+KDV)") : "Pompa fiyatı", sourceUrl, sourceLabel, checkedAt: new Date().toISOString() });
    } catch (err) {
        console.error("[fuel-check]", err);
        return res.status(502).json({ ok: false, error: err.message || "Fiyat kontrolü başarısız." });
    }
});


// ===============================
// FUEL SERVICE — Render live backend
// ===============================
const fuelText = (html = "") => String(html)
  .replace(/&nbsp;|&#160;/gi, " ").replace(/&amp;/gi, "&")
  .replace(/<script[\s\S]*?<\/script>/gi, " ")
  .replace(/<style[\s\S]*?<\/style>/gi, " ")
  .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();

const fuelAscii = (value = "") => String(value).trim().toLocaleUpperCase("tr-TR")
  .replace(/İ/g, "I").replace(/Ş/g, "S").replace(/Ğ/g, "G")
  .replace(/Ü/g, "U").replace(/Ö/g, "O").replace(/Ç/g, "C")
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
  throw new Error(`Petrol Ofisi fiyatı bulunamadı: ${city}/${district} ${fuel}`);
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
  if (!product?.fepProductCode) throw new Error("Shell ürün kodu bulunamadı.");
  return String(product.fepProductCode);
}

function parseShell(data, city, district, fuel) {
  const cityNode = (Array.isArray(data?.groups) ? data.groups : [])
    .find(item => fuelAscii(item?.cityName || "") === fuelAscii(city));
  if (!cityNode) throw new Error(`Shell il bulunamadı: ${city}`);

  const county = (Array.isArray(cityNode.counties) ? cityNode.counties : [])
    .find(item => fuelAscii(item?.countyName || "") === fuelAscii(district));
  if (!county) throw new Error(`Shell ilçe bulunamadı: ${city}/${district}`);

  const code = shellProductCode(data, fuel);
  const prices = county.prices || {};
  const key = Object.keys(prices).find(k => String(k).trim() === code.trim());
  const price = Number(prices[code] ?? (key ? prices[key] : undefined));

  if (!Number.isFinite(price)) throw new Error("Shell fiyatı bulunamadı.");
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
    catch { throw new Error("Shell servisi JSON döndürmedi."); }
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
  { customer:"BİM", provider:"petrol-ofisi", city:"İstanbul", district:"SANCAKTEPE", fuel:"Motorin", vatIncluded:false },
  { customer:"TEVERPAN", provider:"petrol-ofisi", city:"Tekirdağ", district:"ÇERKEZKÖY", fuel:"Motorin", vatIncluded:true },
  { customer:"EFOR ÇAY", provider:"petrol-ofisi", city:"Tokat", district:"ERBAA", fuel:"Motorin", vatIncluded:true },
  { customer:"CORTEVA", provider:"petrol-ofisi", city:"Adana", district:"MERKEZ", fuel:"Motorin", vatIncluded:true },
  { customer:"CMC AGRO", provider:"petrol-ofisi", city:"Bursa", district:"KARACABEY", fuel:"Motorin", vatIncluded:true },
  { customer:"ETİ", provider:"petrol-ofisi", city:"Eskişehir", district:"ODUNPAZARI", fuel:"Motorin", vatIncluded:true },
  { customer:"KWS", provider:"petrol-ofisi", city:"Eskişehir", district:"MERKEZ", fuel:"Motorin", vatIncluded:true },
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

app.listen(PORT, () => {
  console.log(`Backend çalışıyor: port ${PORT} | fuel-check aktif | 5 dk yakıt kontrolü aktif`);
});
