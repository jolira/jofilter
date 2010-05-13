package com.google.code.joliratools.jofilter;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.Key;
import java.util.Date;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A very simple filter for preventing login.
 * 
 * @author jfk
 * @date May 13, 2010 6:26:56 AM
 * @since 1.0
 */
public class LoginFilter implements Filter {
    final static Logger LOG = Logger.getLogger(LoginFilter.class.getName());

    private Key key;
    private String username;
    private String password;
    private String domain;
    private String path;
    private int expiry = 0;

    private boolean verifyRemote;
    static final String USERNAME = "username";
    static final String PASSWORD = "password";
    static final String URL = "url";

    @Override
    public void destroy() {
        // nothing yet
    }

    @Override
    public void doFilter(final ServletRequest req, final ServletResponse resp, final FilterChain chain)
            throws IOException, ServletException {
        final HttpServletRequest _req = (HttpServletRequest) req;
        final HttpServletResponse _resp = (HttpServletResponse) resp;
        String url = null;

        if (!hasValidCookie(_req)) {
            final String _username = req.getParameter(USERNAME);
            final String _password = req.getParameter(PASSWORD);

            if (_username == null || _username.isEmpty() || _password == null || _password.isEmpty()) {
                final CharSequence requestURL = _req.getRequestURL();

                respondWithLoginPage(requestURL, _resp, false);
                return;
            }

            url = req.getParameter(URL);

            if (url == null) {
                throw new Error("unable to complete");
            }

            if (!_username.equals(username) || !_password.equals(password)) {
                final String remoteAddr = req.getRemoteAddr();

                LOG.warning("login for user " + username + '@' + remoteAddr + " failed");
                respondWithLoginPage(url, _resp, true);
                return;
            }
        }

        final String remoteAddr = req.getRemoteAddr();
        final LoginCookieContent content = new LoginCookieContent(remoteAddr, key, domain, expiry, path);
        final Cookie cookie = content.toCookie();

        _resp.addCookie(cookie);

        if (url != null) {
            _resp.sendRedirect(url);
        } else {
            chain.doFilter(req, resp);
        }
    }

    private Cookie findAccessCookie(final HttpServletRequest req) {
        final Cookie[] cookies = req.getCookies();

        return LoginCookieContent.findAccessCookie(cookies);
    }

    private boolean hasValidCookie(final HttpServletRequest req) {
        final Cookie cookie = findAccessCookie(req);

        if (cookie == null) {
            LOG.info("no cookie found");
            return false;
        }

        final LoginCookieContent content = LoginCookieContent.valueOf(cookie, key);

        if (content == null) {
            LOG.info("invalid cookie value");
            return false;
        }

        final long expires = content.getExpires();

        if (expires > 0) {
            final long current = System.currentTimeMillis();

            if (current > expires) {
                final Date expired = new Date(expires);
                LOG.info("cookie expired " + expired);
                return false;
            }
        }

        if (!verifyRemote) {
            return true;
        }

        final String actualRemoteAddress = content.getRemoteAddress();
        final String expectedRemoteAddress = req.getRemoteAddr();

        if (expectedRemoteAddress.equals(actualRemoteAddress)) {
            return true;
        }

        LOG.warning("remote address did not match: expect " + expectedRemoteAddress + "; got " + actualRemoteAddress);

        return false;
    }

    @Override
    public void init(final FilterConfig config) throws ServletException {
        final String keyFile = config.getInitParameter("keyFile");

        try {
            key = readKey(keyFile == null || keyFile.isEmpty() ? LoginCookieContent.class
                    .getResourceAsStream("filter.key") : new FileInputStream(keyFile));
        } catch (final FileNotFoundException e) {
            throw new Error(e);
        } catch (final IOException e) {
            throw new Error(e);
        } catch (final ClassNotFoundException e) {
            throw new Error(e);
        }

        LOG.config("keyFile: " + keyFile);

        username = config.getInitParameter(USERNAME);

        if (username == null) {
            throw new IllegalArgumentException("please specify a " + USERNAME);
        }

        LOG.config("username: " + username);

        password = config.getInitParameter(PASSWORD);

        if (password == null) {
            throw new IllegalArgumentException("please specify a " + PASSWORD);
        }

        domain = config.getInitParameter("domain");
        path = config.getInitParameter("path");

        LOG.config("domain: " + domain);
        LOG.config("path: " + path);

        final String _expiry = config.getInitParameter("expiry");

        if (_expiry != null && !_expiry.isEmpty()) {
            expiry = Integer.parseInt(_expiry);
        }

        LOG.config("expiry: " + expiry);

        final String _verifyRemote = config.getInitParameter("verifyRemote");

        verifyRemote = _verifyRemote != null && Boolean.parseBoolean(_verifyRemote);

        LOG.config("verifyRemote: " + verifyRemote);
    }

    private Key readKey(final InputStream in) throws IOException, ClassNotFoundException {
        final ObjectInputStream oin = new ObjectInputStream(in);

        try {
            return (Key) oin.readObject();
        } finally {
            oin.close();
        }
    }

    private void respondWithLoginPage(final CharSequence requestURL, final HttpServletResponse resp,
            final boolean previouslyFailed) throws IOException {
        resp.setContentType("text/html");
        resp.setHeader("Pragma", "no-cache");
        resp.setDateHeader("Expires", 0);

        final ServletOutputStream out = resp.getOutputStream();

        out.print("<html>");
        out.print("<head>");
        out.print("<meta http-equiv=\"Pragma\" content=\"no-cache\">");
        out.print("<meta http-equiv=\"CACHE-CONTROL\" content=\"no-cache\">");
        out.print("<meta name = \"viewport\" " + "content = \"width =device-width\">");
        out.print("<title>Please Log in!</title>");
        out.print("</head>");
        out.print("<body>");

        if (previouslyFailed) {
            out.print("<i>invalid username and/or password</i><br>");
        }

        out.print("<form method=\"POST\" action=\"#\">");
        out.print("Username: <input type=\"text\" name=\"");
        out.print(USERNAME);
        out.print("\" id=\"");
        out.print(USERNAME);
        out.print("\"/><br>");
        out.print("Password: <input type=\"password\" name=\"");
        out.print(PASSWORD);
        out.print("\" id=\"");
        out.print(PASSWORD);
        out.print("\"/><br>");
        out.print("<input type=\"hidden\" name=\"");
        out.print(URL);
        out.print("\" id=\"");
        out.print(URL);
        out.print("\" value=\"");
        out.print(requestURL.toString());
        out.print("\"/>");
        out.print("<input type=\"submit\" value=\"Log In\"/><br>");
        out.print("</form>");
        out.print("</body>");
        out.print("</html>");
    }
}
