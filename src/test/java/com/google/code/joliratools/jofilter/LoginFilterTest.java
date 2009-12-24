package com.google.code.joliratools.jofilter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.CodeSource;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.Test;

public class LoginFilterTest {
    static class MockFilterConfig implements FilterConfig {
        @Override
        public String getFilterName() {
            fail();
            return null;
        }

        @Override
        public String getInitParameter(final String name) {
            if (LoginFilter.USERNAME.equals(name)) {
                return ACTUAL_USERNAME;
            }

            if (LoginFilter.PASSWORD.equals(name)) {
                return ACTUAL_PASSWORD;
            }

            return null;
        }

        @Override
        public Enumeration<?> getInitParameterNames() {
            fail();
            return null;
        }

        @Override
        public ServletContext getServletContext() {
            fail();
            return null;
        }
    }

    static abstract class MockHttpServletRequest implements HttpServletRequest {
        @Override
        public Object getAttribute(final String name) {
            fail();
            return null;
        }

        @Override
        public Enumeration<?> getAttributeNames() {
            fail();
            return null;
        }

        @Override
        public String getAuthType() {
            fail();
            return null;
        }

        @Override
        public String getCharacterEncoding() {
            fail();
            return null;
        }

        @Override
        public int getContentLength() {
            fail();
            return 0;
        }

        @Override
        public String getContentType() {
            fail();
            return null;
        }

        @Override
        public String getContextPath() {
            fail();
            return null;
        }

        @Override
        public long getDateHeader(final String name) {
            fail();
            return 0;
        }

        @Override
        public String getHeader(final String name) {
            fail();
            return null;
        }

        @Override
        public Enumeration<?> getHeaderNames() {
            fail();
            return null;
        }

        @Override
        public Enumeration<?> getHeaders(final String name) {
            fail();
            return null;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            fail();
            return null;
        }

        @Override
        public int getIntHeader(final String name) {
            fail();
            return 0;
        }

        @Override
        public String getLocalAddr() {
            fail();
            return null;
        }

        @Override
        public Locale getLocale() {
            fail();
            return null;
        }

        @Override
        public Enumeration<?> getLocales() {
            fail();
            return null;
        }

        @Override
        public String getLocalName() {
            fail();
            return null;
        }

        @Override
        public int getLocalPort() {
            fail();
            return 0;
        }

        @Override
        public String getMethod() {
            fail();
            return null;
        }

        @Override
        public Map<?, ?> getParameterMap() {
            fail();
            return null;
        }

        @Override
        public Enumeration<?> getParameterNames() {
            fail();
            return null;
        }

        @Override
        public String[] getParameterValues(final String name) {
            fail();
            return null;
        }

        @Override
        public String getPathInfo() {
            fail();
            return null;
        }

        @Override
        public String getPathTranslated() {
            fail();
            return null;
        }

        @Override
        public String getProtocol() {
            fail();
            return null;
        }

        @Override
        public String getQueryString() {
            fail();
            return null;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            fail();
            return null;
        }

        @Override
        public String getRealPath(final String path) {
            fail();
            return null;
        }

        @Override
        public String getRemoteAddr() {
            return REMOTE_ADDRESS;
        }

        @Override
        public String getRemoteHost() {
            fail();
            return null;
        }

        @Override
        public int getRemotePort() {
            fail();
            return 0;
        }

        @Override
        public String getRemoteUser() {
            fail();
            return null;
        }

        @Override
        public RequestDispatcher getRequestDispatcher(final String path) {
            fail();
            return null;
        }

        @Override
        public String getRequestedSessionId() {
            fail();
            return null;
        }

        @Override
        public String getRequestURI() {
            fail();
            return null;
        }

        @Override
        public StringBuffer getRequestURL() {
            final StringBuffer buf = new StringBuffer();

            buf.append(TEST_URL);

            return buf;
        }

        @Override
        public String getScheme() {
            fail();
            return null;
        }

        @Override
        public String getServerName() {
            fail();
            return null;
        }

        @Override
        public int getServerPort() {
            fail();
            return 0;
        }

        @Override
        public String getServletPath() {
            fail();
            return "/xxx/xxx";
        }

        @Override
        public HttpSession getSession() {
            fail();
            return null;
        }

        @Override
        public HttpSession getSession(final boolean create) {
            fail();
            return null;
        }

        @Override
        public Principal getUserPrincipal() {
            fail();
            return null;
        }

        @Override
        public boolean isRequestedSessionIdFromCookie() {
            fail();
            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromUrl() {
            fail();
            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromURL() {
            fail();
            return false;
        }

        @Override
        public boolean isRequestedSessionIdValid() {
            fail();
            return false;
        }

        @Override
        public boolean isSecure() {
            fail();
            return false;
        }

        @Override
        public boolean isUserInRole(final String role) {
            fail();
            return false;
        }

        @Override
        public void removeAttribute(final String name) {
            fail();

        }

        @Override
        public void setAttribute(final String name, final Object o) {
            fail();

        }

        @Override
        public void setCharacterEncoding(final String env)
                throws UnsupportedEncodingException {
            fail();

        }
    }

    static abstract class MockHttpServletResponse implements
            HttpServletResponse {
        final StringBuilder out;

        MockHttpServletResponse(final StringBuilder out) {
            this.out = out;
        }

        @Override
        public void addCookie(final Cookie cookie) {
            // TODO: Check if cookie is added
        }

        @Override
        public void addDateHeader(final String name, final long date) {
            fail();

        }

        @Override
        public void addHeader(final String name, final String value) {
            fail();

        }

        @Override
        public void addIntHeader(final String name, final int value) {
            fail();

        }

        @Override
        public boolean containsHeader(final String name) {
            fail();
            return false;
        }

        @Override
        public String encodeRedirectUrl(final String url) {
            fail();
            return null;
        }

        @Override
        public String encodeRedirectURL(final String url) {
            fail();
            return null;
        }

        @Override
        public String encodeUrl(final String url) {
            fail();
            return null;
        }

        @Override
        public String encodeURL(final String url) {
            fail();
            return null;
        }

        @Override
        public void flushBuffer() throws IOException {
            fail();

        }

        @Override
        public int getBufferSize() {
            fail();
            return 0;
        }

        @Override
        public String getCharacterEncoding() {
            fail();
            return null;
        }

        @Override
        public String getContentType() {
            fail();
            return null;
        }

        @Override
        public Locale getLocale() {
            fail();
            return null;
        }

        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            return new ServletOutputStream() {
                @Override
                public void write(final int b) throws IOException {
                    out.append((char) b);
                }
            };
        }

        @Override
        public PrintWriter getWriter() throws IOException {
            fail();
            return null;
        }

        @Override
        public boolean isCommitted() {
            fail();
            return false;
        }

        @Override
        public void reset() {
            fail();

        }

        @Override
        public void resetBuffer() {
            fail();

        }

        @Override
        public void sendError(final int sc) throws IOException {
            fail();

        }

        @Override
        public void sendError(final int sc, final String msg)
                throws IOException {
            fail();
        }

        @Override
        public void sendRedirect(final String location) throws IOException {
            fail();
        }

        @Override
        public void setBufferSize(final int size) {
            fail();

        }

        @Override
        public void setCharacterEncoding(final String charset) {
            fail();

        }

        @Override
        public void setContentLength(final int len) {
            fail();

        }

        @Override
        public void setContentType(final String type) {
            fail();

        }

        @Override
        public void setDateHeader(final String name, final long date) {
            // expected to be called

        }

        @Override
        public void setHeader(final String name, final String value) {
            // expected to be called

        }

        @Override
        public void setIntHeader(final String name, final int value) {
            fail();

        }

        @Override
        public void setLocale(final Locale loc) {
            fail();

        }

        @Override
        public void setStatus(final int sc) {
            fail();

        }

        @Override
        public void setStatus(final int sc, final String sm) {
            fail();

        }
    }

    private static final String ACTUAL_PASSWORD = "karen";

    private static final String ACTUAL_USERNAME = "jolira";

    private static final String TEST_URL = "http://jolira.com/myinfo/test?a=b";

    private static final String LOGIN_HTML = "<html><head>"
            + "<meta http-equiv=\"Pragma\" content=\"no-cache\">"
            + "<meta http-equiv=\"CACHE-CONTROL\" content=\"no-cache\">"
            + "<meta name = \"viewport\" content = \"width =device-width\">"
            + "<title>Please Log in!</title></head>" + "<body>"
            + "<form method=\"POST\" action=\"#\">"
            + "Username: <input type=\"text\" name=\"" + LoginFilter.USERNAME
            + "\" id=\"" + LoginFilter.USERNAME + "\"><br>"
            + "Password: <input type=\"password\" name=\""
            + LoginFilter.PASSWORD + "\" id=\"" + LoginFilter.PASSWORD
            + "\"><br><input type=\"hidden\" name=\"" + LoginFilter.URL
            + "\" id=\"" + LoginFilter.URL
            + "\" value=\"http://jolira.com/myinfo/test?a=b\">"
            + "<input type=\"submit\" value=\"Log In\"><br></input></form>"
            + "</body></html>";

    private static final String INVALID_LOGIN_HTML = "<html><head>"
            + "<meta http-equiv=\"Pragma\" content=\"no-cache\">"
            + "<meta http-equiv=\"CACHE-CONTROL\" content=\"no-cache\">"
            + "<meta name = \"viewport\" content = \"width =device-width\">"
            + "<title>Please Log in!</title></head>" + "<body>"
            + "<i>invalid username and/or password</i><br>"
            + "<form method=\"POST\" action=\"#\">"
            + "Username: <input type=\"text\" name=\"" + LoginFilter.USERNAME
            + "\" id=\"" + LoginFilter.USERNAME + "\"><br>"
            + "Password: <input type=\"password\" name=\""
            + LoginFilter.PASSWORD + "\" id=\"" + LoginFilter.PASSWORD
            + "\"><br><input type=\"hidden\" name=\"" + LoginFilter.URL
            + "\" id=\"" + LoginFilter.URL
            + "\" value=\"http://jolira.com/myinfo/test?a=b\">"
            + "<input type=\"submit\" value=\"Log In\"><br></input></form>"
            + "</body></html>";

    private static final String REMOTE_ADDRESS = "theRemoteAddress";

    public static void main(final String[] args)
            throws NoSuchAlgorithmException, IOException {
        if (args.length < 1) {
            throw new Error("Please specifiy a file name to store the key.");
        }

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("Blowfish");

        keyGenerator.init(128);

        final Key key = keyGenerator.generateKey();
        final OutputStream out = new FileOutputStream(args[0]);
        final ObjectOutputStream oout = new ObjectOutputStream(out);

        try {
            oout.writeObject(key);
        } finally {
            oout.close();
        }
    }

    @Test
    public void testInvalidLogin() throws ServletException, IOException {
        final Filter filter = new LoginFilter();
        final StringBuilder out = new StringBuilder();
        final String[] locations = { null };

        filter.init(new MockFilterConfig());
        filter.doFilter(new MockHttpServletRequest() {
            @Override
            public Cookie[] getCookies() {
                return null;
            }

            @Override
            public String getParameter(final String name) {
                if (LoginFilter.USERNAME.equals(name)) {
                    return ACTUAL_USERNAME;
                }

                if (LoginFilter.PASSWORD.equals(name)) {
                    return "incorrect";
                }

                if (LoginFilter.URL.equals(name)) {
                    return TEST_URL;
                }

                return null;
            }
        }, new MockHttpServletResponse(out) {
            @Override
            public void sendRedirect(final String location) throws IOException {
                locations[0] = location;
            }

            // nothing in this test
        }, new FilterChain() {
            @Override
            public void doFilter(final ServletRequest request,
                    final ServletResponse response) throws IOException,
                    ServletException {
                fail();
            }
        });
        filter.destroy();

        assertNull(locations[0]);

        final String result = out.toString();

        assertEquals(INVALID_LOGIN_HTML, result);
    }

    @Test
    public void testKeyFileInConfig() throws ServletException {
        final Filter filter = new LoginFilter();

        filter.init(new MockFilterConfig() {
            @Override
            public String getInitParameter(final String name) {
                if (!"keyFile".equals(name)) {
                    return super.getInitParameter(name);
                }

                final ProtectionDomain pd = LoginFilter.class
                        .getProtectionDomain();
                final CodeSource cs = pd.getCodeSource();
                final URL loc = cs.getLocation();
                final String file = loc.getFile();
                final File _file = new File(file);
                final File directory = _file.getParentFile();
                final Package pkg = LoginFilter.class.getPackage();
                final String _pkgName = pkg.getName();
                final String pkgName = _pkgName.replace('.', '/');
                final File keyFile = new File(directory, "classes/" + pkgName
                        + "/filter.key");

                return keyFile.getAbsolutePath();
            }
        });
    }

    @Test
    public void testLogin() throws ServletException, IOException {
        final Filter filter = new LoginFilter();
        final StringBuilder out = new StringBuilder();
        final String[] locations = { null };

        filter.init(new MockFilterConfig());
        filter.doFilter(new MockHttpServletRequest() {
            @Override
            public Cookie[] getCookies() {
                return null;
            }

            @Override
            public String getParameter(final String name) {
                if (LoginFilter.USERNAME.equals(name)) {
                    return ACTUAL_USERNAME;
                }

                if (LoginFilter.PASSWORD.equals(name)) {
                    return ACTUAL_PASSWORD;
                }

                if (LoginFilter.URL.equals(name)) {
                    return TEST_URL;
                }

                return null;
            }
        }, new MockHttpServletResponse(out) {
            @Override
            public void sendRedirect(final String location) throws IOException {
                locations[0] = location;
            }

            // nothing in this test
        }, new FilterChain() {
            @Override
            public void doFilter(final ServletRequest request,
                    final ServletResponse response) throws IOException,
                    ServletException {
                fail();
            }
        });
        filter.destroy();

        assertEquals(locations[0], TEST_URL);

        final String result = out.toString();

        assertTrue(result.isEmpty());
    }

    @Test
    public void testNoCookies() throws ServletException, IOException {
        final Filter filter = new LoginFilter();
        final StringBuilder out = new StringBuilder();

        filter.init(new MockFilterConfig());
        filter.doFilter(new MockHttpServletRequest() {
            @Override
            public Cookie[] getCookies() {
                return new Cookie[] {};
            }

            @Override
            public String getParameter(final String name) {
                return null;
            }
        }, new MockHttpServletResponse(out) {
            // nothing in this test
        }, new FilterChain() {
            @Override
            public void doFilter(final ServletRequest request,
                    final ServletResponse response) throws IOException,
                    ServletException {
                fail();
            }
        });
        filter.destroy();

        final String result = out.toString();

        assertEquals(LOGIN_HTML, result);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNoPasswordInConfig() throws ServletException {
        final Filter filter = new LoginFilter();

        filter.init(new MockFilterConfig() {
            @Override
            public String getInitParameter(final String name) {
                if (!LoginFilter.PASSWORD.equals(name)) {
                    return super.getInitParameter(name);
                }

                return null;
            }
        });
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNoUsernameInConfig() throws ServletException {
        final Filter filter = new LoginFilter();

        filter.init(new MockFilterConfig() {
            @Override
            public String getInitParameter(final String name) {
                return null;
            }
        });
    }

    @Test
    public void testNullCookies() throws ServletException, IOException {
        final Filter filter = new LoginFilter();
        final StringBuilder out = new StringBuilder();

        filter.init(new MockFilterConfig());
        filter.doFilter(new MockHttpServletRequest() {
            @Override
            public Cookie[] getCookies() {
                return null;
            }

            @Override
            public String getParameter(final String name) {
                return null;
            }
        }, new MockHttpServletResponse(out) {
            // nothing in this test
        }, new FilterChain() {
            @Override
            public void doFilter(final ServletRequest request,
                    final ServletResponse response) throws IOException,
                    ServletException {
                fail();
            }
        });
        filter.destroy();

        final String result = out.toString();

        assertEquals(LOGIN_HTML, result);
    }

    @Test
    public void testValidCookie() throws ServletException, IOException,
            ClassNotFoundException {
        final Filter filter = new LoginFilter();
        final Key key = LoginCookieContentTest.readKey();
        final LoginCookieContent content = new LoginCookieContent(
                REMOTE_ADDRESS, key, null, 0, null);
        final Cookie cookie = content.toCookie();
        final StringBuilder out = new StringBuilder();

        filter.init(new MockFilterConfig());
        filter.doFilter(new MockHttpServletRequest() {
            @Override
            public Cookie[] getCookies() {
                return new Cookie[] { cookie };
            }

            @Override
            public String getParameter(final String name) {
                return null;
            }
        }, new MockHttpServletResponse(out) {
            // nothing in this test
        }, new FilterChain() {
            @Override
            public void doFilter(final ServletRequest request,
                    final ServletResponse response) throws IOException,
                    ServletException {
                final ServletOutputStream _out = response.getOutputStream();

                _out.print("success");
            }
        });
        filter.destroy();

        final String result = out.toString();

        assertEquals("success", result);
    }

    @Test
    public void testValidLogin() throws ServletException, IOException,
            ClassNotFoundException {
        final Filter filter = new LoginFilter();
        final Key key = LoginCookieContentTest.readKey();
        final LoginCookieContent content = new LoginCookieContent(
                REMOTE_ADDRESS, key, null, 0, null);
        final Cookie cookie = content.toCookie();
        final StringBuilder out = new StringBuilder();

        filter.init(new MockFilterConfig());
        filter.doFilter(new MockHttpServletRequest() {
            @Override
            public Cookie[] getCookies() {
                return new Cookie[] { cookie };
            }

            @Override
            public String getParameter(final String name) {
                return null;
            }
        }, new MockHttpServletResponse(out) {
            // nothing in this test
        }, new FilterChain() {
            @Override
            public void doFilter(final ServletRequest request,
                    final ServletResponse response) throws IOException,
                    ServletException {
                final ServletOutputStream _out = response.getOutputStream();

                _out.print("success");
            }
        });
        filter.destroy();

        final String result = out.toString();

        assertEquals("success", result);
    }
}
