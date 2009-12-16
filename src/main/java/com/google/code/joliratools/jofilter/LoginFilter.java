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

    @Override
    public void destroy() {
        // nothing yet
    }

    @Override
    public void doFilter(final ServletRequest req, final ServletResponse resp,
            final FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest _req = (HttpServletRequest) req;
        final HttpServletResponse _resp = (HttpServletResponse) resp;

        if (hasValidCookie(_req)) {
            chain.doFilter(req, resp);
            return;
        }

        final CharSequence requestURL = _req.getRequestURL();

        respondWithLoginPage(requestURL, _resp);
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
            final HttpServletResponse resp) throws IOException {
        final ServletOutputStream out = resp.getOutputStream();

        out.println("<html>");
        out.println("<head>");
        out.println("<title>Please Log in!</title>");
        out.println("</head>");
        out.println("<body>");
        out.println("<form method=\"POST\" action=\"jo_security_check\">");
        out.println("Username: <input type=\"text\" name=\"username\"><br>");
        out.println("Password: <input type=\"password\" name=\"password\">");
        out.println("<input type=\"hidden\" name=\"url\">" + requestURL
                + "</input>");
        out.println("</form>");
        out.println("</body>");
        out.println("</html>");
    }

}
