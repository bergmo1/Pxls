package space.pxls.util;

import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.Cookie;
import io.undertow.server.handlers.CookieImpl;
import io.undertow.util.AttachmentKey;
import space.pxls.App;
import space.pxls.user.User;
import space.pxls.user.UserLogin;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

public class AuthReader implements HttpHandler {
    public static AttachmentKey<User> USER =
            AttachmentKey.create(User.class);

    private static final ConcurrentHashMap<String, String> loginCache =
            new ConcurrentHashMap<>();

    private static final SecureRandom RANDOM = new SecureRandom();

    private final HttpHandler next;

    public AuthReader(HttpHandler next) {
        this.next = next;
    }

    @Override
    public void handleRequest(HttpServerExchange exchange)
            throws Exception {

        if (!App.getConfig().getBoolean("oauth.useIp")) {
            Cookie header = exchange.getRequestCookie("pxls-token");

            if (header != null) {
                User user = App.getUserManager()
                        .getByToken(header.getValue());

                if (user != null) {
                    exchange.putAttachment(USER, user);
                }
            }
        } else {
            String ip = exchange.getAttachment(IPReader.IP);

            // Get the browser's anonymous identity cookie.
            Cookie anonCookie =
                    exchange.getRequestCookie("pxls-anon");

            String sessionId;

            if (anonCookie != null &&
                    anonCookie.getValue()
                            .matches("[A-Za-z0-9_-]{43}")) {
                sessionId = anonCookie.getValue();
            } else {
                // Generate a unique, unpredictable browser identity.
                byte[] randomBytes = new byte[32];
                RANDOM.nextBytes(randomBytes);

                sessionId = Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(randomBytes);

                // Set a browser-session cookie.
                CookieImpl cookie =
                        new CookieImpl("pxls-anon", sessionId);

                cookie.setPath("/");
                cookie.setHttpOnly(true);
                cookie.setSecure(
                        App.getConfig().getBoolean("https"));

                exchange.getResponseCookies()
                        .put(cookie.getName(), cookie);
            }

            final User[] user = new User[1];

            // Cache by browser identity, NOT by IP address.
            loginCache.compute(sessionId, (key, oldToken) -> {
                if (oldToken != null) {
                    User cached = App.getUserManager()
                            .getByToken(oldToken);

                    if (cached != null) {
                        user[0] = cached;
                        return oldToken;
                    }
                }

                // Look up this browser's anonymous account.
                user[0] = App.getUserManager()
                        .getByLogin("ip", key);

                if (user[0] == null) {
                    String signupToken = App.getUserManager()
                            .generateUserCreationToken(
                                    new UserLogin("ip", key));

                    user[0] = App.getUserManager()
                            .signUp(
                                    MD5.compute(key),
                                    signupToken,
                                    ip);

                    // In case the account already exists.
                    if (user[0] == null) {
                        user[0] = App.getUserManager()
                                .getByLogin("ip", key);
                    }
                }

                if (user[0] == null) {
                    throw new IllegalStateException(
                            "Could not create anonymous browser user");
                }

                return App.getUserManager().logIn(user[0], ip);
            });

            exchange.putAttachment(USER, user[0]);
        }

        next.handleRequest(exchange);
    }
}
