const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.post("/odak", async (req, res) => {
    try {
        const response = await fetch("https://api.odaklojistik.com.tr/api/tmsorders/getall", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: process.env.ODAK_API_KEY,
            },
            body: JSON.stringify(req.body),
        });

        const data = await response.json();
        res.status(200).json(data);
    } catch (error) {
        console.error("Odak API proxy hatası:", error.message);
        res.status(500).json({ error: "Proxy isteği başarısız", details: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Proxy sunucu çalışıyor: http://localhost:${PORT}`);
});
