package com.google.code.joliratools.jofilter;

import static java.util.logging.Level.FINE;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.Cookie;

class LoginCookieContent implements Serializable {
    final static Logger LOG = Logger.getLogger(LoginCookieContent.class.getName());

    private static final String ALGORITHM = "Blowfish";
    private static final long serialVersionUID = 7579773293494069499L;
    static final String ACCESS_COOKIE_NAME = "AccessVerificationCookie";

    static Cookie findAccessCookie(final Cookie[] cookies) {
        final boolean loggable = LOG.isLoggable(FINE);

        if (cookies == null) {
            if (loggable) {
                LOG.fine("no cookies found");
            }

            return null;
        }

        for (final Cookie cookie : cookies) {
            final String name = cookie.getName();

            if (ACCESS_COOKIE_NAME.equals(name)) {
                if (loggable) {
                    LOG.fine("found cookie" + name + ": " + cookie);
                }

                return cookie;
            }

            if (loggable) {
                LOG.fine("skipping cookie " + name + ": " + cookie);
            }
        }

        return null;
    }

    private static LoginCookieContent read(final String value, final Key key) throws IOException,
            ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        final Cipher chipher = Cipher.getInstance(ALGORITHM);

        chipher.init(DECRYPT_MODE, key);

        final byte[] decoded = Base64Coder.decode(value);
        final InputStream in = new ByteArrayInputStream(decoded);
        final InputStream cin = new CipherInputStream(in, chipher);
        final ObjectInputStream oin = new ObjectInputStream(cin);

        try {
            return (LoginCookieContent) oin.readObject();
        } finally {
            oin.close();
        }
    }

    public static LoginCookieContent valueOf(final Cookie cookie, final Key key) {
        final String value = cookie.getValue();

        try {
            return read(value, key);
        } catch (final IOException e) {
            throw new Error(e);
        } catch (final ClassNotFoundException e) {
            throw new Error(e);
        } catch (final InvalidKeyException e) {
            throw new Error(e);
        } catch (final NoSuchAlgorithmException e) {
            throw new Error(e);
        } catch (final NoSuchPaddingException e) {
            throw new Error(e);
        }
    }

    private final String remoteAddress;
    private final long expires;
    private transient final Key key;
    private transient final String domain;
    private transient final int expiry;
    private transient final String path;

    LoginCookieContent(final String remoteAddress, final Key key, final String domain, final int expiry,
            final String path) {
        this.domain = domain;
        this.expiry = expiry;
        this.path = path;

        long _expires = 0;

        if (expiry > 0) {
            final long current = System.currentTimeMillis();

            _expires = current + 1000 * expiry;
        }

        expires = _expires;

        if (remoteAddress == null) {
            throw new IllegalArgumentException("remote address was null");
        }

        if (key == null) {
            throw new IllegalArgumentException("A key must be provided");
        }

        this.remoteAddress = remoteAddress;
        this.key = key;
    }

    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof LoginCookieContent)) {
            return false;
        }
        final LoginCookieContent other = (LoginCookieContent) obj;
        if (getExpires() != other.getExpires()) {
            return false;
        }
        if (remoteAddress == null) {
            if (other.remoteAddress != null) {
                return false;
            }
        } else if (!remoteAddress.equals(other.remoteAddress)) {
            return false;
        }
        return true;
    }

    public long getExpires() {
        return expires;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (getExpires() ^ getExpires() >>> 32);
        result = prime * result + (remoteAddress == null ? 0 : remoteAddress.hashCode());
        return result;
    }

    public Cookie toCookie() {
        String val;

        try {
            val = write();
        } catch (final IOException e) {
            throw new Error(e);
        } catch (final NoSuchAlgorithmException e) {
            throw new Error(e);
        } catch (final NoSuchPaddingException e) {
            throw new Error(e);
        } catch (final InvalidKeyException e) {
            throw new Error(e);
        }

        final Cookie cookie = new Cookie(ACCESS_COOKIE_NAME, val);

        if (domain != null && !domain.isEmpty()) {
            cookie.setDomain(domain);
        }

        if (expiry > 0) {
            cookie.setMaxAge(expiry);
        }

        cookie.setPath(path != null && !path.isEmpty() ? path : "/");

        return cookie;
    }

    private String write() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        final Cipher cipher = Cipher.getInstance(ALGORITHM);

        cipher.init(ENCRYPT_MODE, key);

        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final OutputStream cout = new CipherOutputStream(out, cipher);
        final ObjectOutputStream oout = new ObjectOutputStream(cout);

        try {
            oout.writeObject(this);
        } finally {
            oout.close();
        }

        final byte[] _val = out.toByteArray();
        final char[] encoded = Base64Coder.encode(_val);

        return new String(encoded);
    }
}
