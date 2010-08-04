/**
 *
 */
package com.google.code.joliratools.jofilter;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;

/**
 * @author jfk
 */
public class Base64CoderTest {

    /**
     * Test encoding & decoding
     */
    @Test
    public void testEncodeDecode() {
        final int size = (Byte.MAX_VALUE - Byte.MIN_VALUE) * 2;
        final byte[] buf = new byte[size];
        int idx = 0;

        for (byte b = Byte.MIN_VALUE; b < Byte.MAX_VALUE; b++) {
            buf[idx++] = b;
        }

        for (byte b = Byte.MAX_VALUE; b > Byte.MIN_VALUE; b--) {
            buf[idx++] = b;
        }

        final char[] encoded = Base64Coder.encode(buf);
        final String _endoced = new String(encoded);
        final byte[] decoded = Base64Coder.decode(_endoced);

        assertArrayEquals(buf, decoded);
    }
}
