const fetch = require("node-fetch");

function config() {
    const url = String(process.env.SUPABASE_URL || "").replace(/\/+$/, "");
    const key = String(process.env.SUPABASE_SERVICE_ROLE_KEY || "");

    if (!url || !key) {
        throw new Error("Supabase server configuration missing.");
    }

    return { url, key };
}

async function request(path, options = {}) {
    const { url, key } = config();

    const response = await fetch(`${url}/rest/v1/${path}`, {
        ...options,
        headers: {
            apikey: key,
            Authorization: `Bearer ${key}`,
            "Content-Type": "application/json",
            ...(options.headers || {}),
        },
    });

    const raw = await response.text();

    let data = null;

    if (raw) {
        try {
            data = JSON.parse(raw);
        } catch {
            data = raw;
        }
    }

    if (!response.ok) {
        throw new Error(
            `Supabase request failed (${response.status})`
        );
    }

    return data;
}

module.exports = {
    request,
};
