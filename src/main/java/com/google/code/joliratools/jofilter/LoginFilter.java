package com.google.code.joliratools.jofilter;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.security.Key;

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

public class LoginFilter implements Filter {
    static final class CookieContent implements Serializable {
        private static final long serialVersionUID = -6069239866160436387L;

        String requestedURL;
        String remoteAddr;
    }

    private Key key;
    private String username;
    private String password;
    private String domain;
    private String path;
    private int expiry = 0;

    static final String LOGIN_SERVLET = "___jo__security__check___";
    static final String USERNAME = "username";
    static final String PASSWORD = "password";

    @Override
    public void destroy() {
        // nothing yet
    }

    @Override
    public void doFilter(final ServletRequest req, final ServletResponse resp,
            final FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest _req = (HttpServletRequest) req;
        final HttpServletResponse _resp = (HttpServletResponse) resp;
        String url = null;

        if (!hasValidCookie(_req)) {
            final String servletPath = _req.getServletPath();

            if (servletPath == null
                    || !servletPath.endsWith("/" + LOGIN_SERVLET)) {
                final CharSequence requestURL = _req.getRequestURL();

                respondWithLoginPage(requestURL, _resp, false);
                return;
            }

            url = req.getParameter("url");

            if (url == null) {
                throw new Error("unable to complete");
            }

            if (!isValidUsernamePassword(_req)) {
                respondWithLoginPage(url, _resp, true);
                return;
            }
        }

        final String remoteAddr = req.getRemoteAddr();
        final LoginCookieContent content = new LoginCookieContent(remoteAddr,
                key, domain, expiry, path);
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
            return false;
        }

        final LoginCookieContent content = LoginCookieContent.valueOf(cookie,
                key);

        if (content == null) {
            return false;
        }

        final long expires = content.getExpires();

        if (expires > 0) {
            final long current = System.currentTimeMillis();

            if (current > expires) {
                return false;
            }
        }

        final String actualRemoteAddress = content.getRemoteAddress();
        final String expectedRemoteAddress = req.getRemoteAddr();

        return expectedRemoteAddress.equals(actualRemoteAddress);
    }

    @Override
    public void init(final FilterConfig config) throws ServletException {
        final String keyFile = config.getInitParameter("keyFile");

        try {
            key = readKey(keyFile == null || keyFile.isEmpty() ? LoginCookieContent.class
                    .getResourceAsStream("filter.key")
                    : new FileInputStream(keyFile));
        } catch (final FileNotFoundException e) {
            throw new Error(e);
        } catch (final IOException e) {
            throw new Error(e);
        } catch (final ClassNotFoundException e) {
            throw new Error(e);
        }

        username = config.getInitParameter(USERNAME);

        if (username == null) {
            throw new IllegalArgumentException("please specify a " + USERNAME);
        }

        password = config.getInitParameter(PASSWORD);

        if (password == null) {
            throw new IllegalArgumentException("please specify a " + PASSWORD);
        }

        domain = config.getInitParameter("domain");
        path = config.getInitParameter("path");

        final String _expiry = config.getInitParameter("expiry");

        if (_expiry != null && !_expiry.isEmpty()) {
            expiry = Integer.parseInt(_expiry);
        }
    }

    private boolean isValidUsernamePassword(final HttpServletRequest req) {
        final String _username = req.getParameter(USERNAME);

        if (!username.equals(_username)) {
            return false;
        }

        final String _password = req.getParameter(PASSWORD);

        return password.equals(_password);
    }

    private Key readKey(final InputStream in) throws IOException,
            ClassNotFoundException {
        final ObjectInputStream oin = new ObjectInputStream(in);

        try {
            return (Key) oin.readObject();
        } finally {
            oin.close();
        }
    }

    private void respondWithLoginPage(final CharSequence requestURL,
            final HttpServletResponse resp, final boolean previouslyFailed)
            throws IOException {
        final ServletOutputStream out = resp.getOutputStream();

        out.print("<html>");
        out.print("<head>");
        out.print("<title>Please Log in!</title>");
        out.print("</head>");
        out.print("<body>");

        if (previouslyFailed) {
            out.print("<i>invalid username and/or password</i><br>");
        }

        out.print("<form method=\"POST\" action=\"");
        out.print(LOGIN_SERVLET);
        out.print("\">");
        out.print("Username: <input type=\"text\" name=\"" + USERNAME
                + "\"><br>");
        out.print("Password: <input type=\"password\" name=\"" + PASSWORD
                + "\"><br>");
        out.print("<input type=\"hidden\" name=\"url\" value=\"");
        out.print(requestURL.toString());
        out.print("\">");
        out.print("<input type=\"submit\" value=\"Log In\"><br>");
        out.print("</input>");
        out.print("</form>");
        out.print("</body>");
        out.print("</html>");
    }
}
