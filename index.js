const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

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
app.post("/reel-auth/api/auth/login", async (req, res) => {
    try {
        const upstream = await fetch("https://tms.odaklojistik.com.tr/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(req.body ?? {}),
        });

        const text = await upstream.text();
        res.status(upstream.status).send(text);
    } catch (err) {
        res.status(500).json({ error: "Auth proxy error", detail: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Backend çalışıyor: http://localhost:${PORT}`);
});