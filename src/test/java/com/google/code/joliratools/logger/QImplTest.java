/**
 * 
 */
package com.google.code.joliratools.logger;

import static org.junit.Assert.assertEquals;

import java.util.logging.Level;
import java.util.logging.LogRecord;

import org.junit.Test;

public class QImplTest {
    private final static int QSIZE = 84;

    @Test
    public void testQ() {
        final QImpl q = new QImpl(QSIZE);

        testQ(q);
    }

    private void testQ(final QImpl q) {
        for (int idx = 0; idx < QSIZE * QSIZE; idx++) {
            final String _idx = Integer.toString(idx);

            q.enqueue(new LogRecord(new Level(_idx, idx) {
                private static final long serialVersionUID = 249773977437176644L;
            }, _idx));
        }

        final LogRecord[] records = q.dequeue();

        assertEquals(QSIZE, records.length);

        for (int idx = 0; idx < QSIZE; idx++) {
            final int val = (QSIZE - 1) * QSIZE + idx;
            final String _val = Integer.toString(val);
            final LogRecord record = records[idx];
            final Level level = record.getLevel();
            final int lvalue = level.intValue();
            final String lname = level.getName();
            final String message = record.getMessage();

            assertEquals(val, lvalue);
            assertEquals(_val, lname);
            assertEquals(_val, message);
        }
    }

    @Test
    public void testQRepeatedly() {
        final QImpl q = new QImpl(QSIZE);

        for (int idx = 0; idx < QSIZE; idx++) {
            testQ(q);
        }
    }

}
