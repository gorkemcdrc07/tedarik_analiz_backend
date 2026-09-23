require("dotenv").config();

const { request } = require("../auth/supabase");

const {
    encryptReelSecret,
    decryptReelSecret,
    isEncrypted
} = require("../auth/reelCrypto");

const APPLY = process.argv.includes("--apply");

async function main() {
    const rows = await request(
        "Login?select=id,Reel_sifre&order=id.asc"
    );

    const stats = {
        total: 0,
        empty: 0,
        plaintext: 0,
        encrypted: 0,
        invalid: 0,
        verified: 0,
        migrated: 0
    };

    stats.total = Array.isArray(rows)
        ? rows.length
        : 0;

    for (const row of rows || []) {
        const value = row?.Reel_sifre;

        if (
            value === null ||
            value === undefined ||
            String(value).trim() === ""
        ) {
            stats.empty++;
            continue;
        }

        const original = String(value);

        if (isEncrypted(original)) {
            try {
                decryptReelSecret(original);
                stats.encrypted++;
            } catch {
                stats.invalid++;
            }

            continue;
        }

        stats.plaintext++;

        /*
         * Plaintext deger terminale/loglara
         * kesinlikle yazdirilmaz.
         */
        const encrypted =
            encryptReelSecret(original);

        const decrypted =
            decryptReelSecret(encrypted);

        if (decrypted !== original) {
            throw new Error(
                `Credential round-trip dogrulamasi basarisiz. User ID: ${row.id}`
            );
        }

        stats.verified++;

        if (!APPLY) {
            continue;
        }

        /*
         * Optimistic concurrency:
         * Credential degerini URL filtresine koymayiz.
         *
         * PATCH'ten hemen once kaydi tekrar okuyup
         * Reel_sifre degerinin degismedigini kontrol ederiz.
         */
        const currentRows = await request(
            `Login?id=eq.${encodeURIComponent(row.id)}` +
            `&select=id,Reel_sifre`
        );

        if (
            !Array.isArray(currentRows) ||
            currentRows.length !== 1
        ) {
            throw new Error(
                `Migration kaydi tekrar okunamadi. User ID: ${row.id}`
            );
        }

        const currentValue =
            currentRows[0]?.Reel_sifre;

        if (
            currentValue === null ||
            currentValue === undefined ||
            String(currentValue) !== original
        ) {
            throw new Error(
                `Migration concurrency kontrolu basarisiz. User ID: ${row.id}`
            );
        }

        const updated = await request(
            `Login?id=eq.${encodeURIComponent(row.id)}`,
            {
                method: "PATCH",

                headers: {
                    Prefer: "return=representation"
                },

                body: JSON.stringify({
                    Reel_sifre: encrypted
                })
            }
        );

        if (
            !Array.isArray(updated) ||
            updated.length !== 1
        ) {
            throw new Error(
                `Migration PATCH basarisiz. User ID: ${row.id}`
            );
        }

        stats.migrated++;
    }

    console.log(
        "MOD =",
        APPLY ? "APPLY" : "DRY-RUN"
    );

    console.log(
        "TOPLAM KULLANICI =",
        stats.total
    );

    console.log(
        "REEL BOS =",
        stats.empty
    );

    console.log(
        "REEL PLAINTEXT =",
        stats.plaintext
    );

    console.log(
        "REEL AES-GCM =",
        stats.encrypted
    );

    console.log(
        "REEL GECERSIZ =",
        stats.invalid
    );

    console.log(
        "ROUND-TRIP VERIFIED =",
        stats.verified
    );

    console.log(
        "MIGRATE EDILEN =",
        stats.migrated
    );

    console.log(
        "REEL SIFRE DEGERLERI EKRANA YAZDIRILMADI."
    );

    if (!APPLY) {
        console.log(
            "DRY-RUN: VERITABANINDA HICBIR DEGISIKLIK YAPILMADI."
        );
    }
}

main().catch((error) => {
    console.error(
        "MIGRATION HATASI =",
        error?.message || "Bilinmeyen hata"
    );

    process.exitCode = 1;
});