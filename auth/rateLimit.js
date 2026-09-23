const { rateLimit } = require("express-rate-limit");

function jsonHandler(message) {
    return (req, res) => {
        const retryAfter = res.getHeader("Retry-After");

        return res.status(429).json({
            error: message,
            retryAfter: retryAfter
                ? Number(retryAfter)
                : undefined,
        });
    };
}

/*
 * Katman 1:
 * Kullanici adi / sifre endpoint'i.
 *
 * Hesap bazli lock auth2fa.js icinde ayrica uygulanir.
 * Bu middleware HTTP/IP seviyesinde ek korumadir.
 */
const loginStartLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,

    standardHeaders: "draft-7",
    legacyHeaders: false,

    skipSuccessfulRequests: true,

    handler: jsonHandler(
        "Cok fazla giris istegi. Lutfen daha sonra tekrar deneyin."
    ),
});

/*
 * Katman 2:
 * TOTP endpoint'i.
 *
 * Challenge kendi icinde 5 yanlis kod ile sinirlidir.
 * Bu limiter challenge ID degistirilerek yapilabilecek
 * seri denemelere karsi IP seviyesinde ikinci katmandir.
 */
const totpVerifyLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    limit: 30,

    standardHeaders: "draft-7",
    legacyHeaders: false,

    skipSuccessfulRequests: true,

    handler: jsonHandler(
        "Cok fazla dogrulama istegi. Lutfen daha sonra tekrar deneyin."
    ),
});

module.exports = {
    loginStartLimiter,
    totpVerifyLimiter,
};