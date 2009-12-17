package com.google.code.joliratools.jofilter;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.Key;

import javax.servlet.http.Cookie;

import org.junit.Test;

public class LoginCookieContentTest {

    static Key readKey() throws IOException, ClassNotFoundException {
        final InputStream in = LoginCookieContent.class
                .getResourceAsStream("filter.key");
        final ObjectInputStream oin = new ObjectInputStream(in);

        try {
            return (Key) oin.readObject();
        } finally {
            oin.close();
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidKey() {
        new LoginCookieContent("myaddr", null, null, 0, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidRemoteAddress() {
        new LoginCookieContent(null, null, null, 0, null);
    }

    @Test
    public void testLoginCookieContent() throws IOException,
            ClassNotFoundException {
        final Key key = readKey();
        final LoginCookieContent content1 = new LoginCookieContent("myaddr",
                key, null, 0, null);
        final Cookie cookie = content1.toCookie();
        final LoginCookieContent content2 = LoginCookieContent.valueOf(cookie,
                key);

        assertEquals(content1, content2);
        assertEquals("myaddr", content2.getRemoteAddress());
        assertEquals("myaddr", content1.getRemoteAddress());

        System.out.println("Encrypted cookie value:");
        System.out.println(cookie.getValue());
    }
}
