/**
 * 
 */
package com.google.code.joliratools.logger;

import static com.google.code.joliratools.logger.Dispatcher.DEFAULT_QSIZE;
import static org.junit.Assert.assertEquals;

import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.Test;

public class DispatcherTest {
    @Test
    public void testDispatcher() {
        final String cname = DispatcherTest.class.getName();
        final Logger logger = Logger.getLogger(cname);
        final Dispatcher dispatcher = new Dispatcher();

        Queue q = dispatcher.addQueue();

        logger.addHandler(dispatcher);

        for (int idx = 0; idx <= DEFAULT_QSIZE; idx++) {
            logger.severe("test" + idx);
        }

        final LogRecord[] records = q.dequeue();

        assertEquals(DEFAULT_QSIZE, records.length);

        for (int idx = 1; idx <= DEFAULT_QSIZE; idx++) {
            final LogRecord record = records[idx - 1];
            final String msg = record.getMessage();

            assertEquals("test" + idx, msg);
        }

        // May trigger the rest of the code
        q = null;
        System.gc();
        logger.severe("test");
    }
}
