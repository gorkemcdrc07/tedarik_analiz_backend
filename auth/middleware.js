const {
    COOKIE_NAME,
    getSessionByToken,
    touchSession,
    clearSessionCookie,
} = require("./session");

async function requireAuth(
    req,
    res,
    next
) {
    try {
        const token =
            req.cookies?.[COOKIE_NAME];

        if (!token) {
            return res.status(401).json({
                error:
                    "Oturum bulunamadi.",
            });
        }

        const session =
            await getSessionByToken(token);

        if (!session) {
            clearSessionCookie(res);

            return res.status(401).json({
                error:
                    "Oturum gecersiz veya suresi dolmus.",
            });
        }

        req.auth = {
            sessionId: session.id,
            userKey: session.user_key,
            session,
        };

        touchSession(session).catch(
            (error) => {
                console.error(
                    "[SESSION TOUCH]",
                    error?.message
                );
            }
        );

        return next();
    } catch (error) {
        console.error(
            "[AUTH MIDDLEWARE]",
            error?.message ||
                "Authentication error"
        );

        return res.status(500).json({
            error:
                "Oturum dogrulanamadi.",
        });
    }
}

module.exports = {
    requireAuth,
};
