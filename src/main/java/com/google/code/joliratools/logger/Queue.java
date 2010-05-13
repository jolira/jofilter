package com.google.code.joliratools.logger;

import java.util.logging.LogRecord;

/**
 * The read-end of the log record queue.
 * 
 * @author jfk
 * @date May 13, 2010 6:25:18 AM
 * @since 1.0
 */
public interface Queue {
    /**
     * Take all currents from the queue.
     * 
     * @return all current records in the queue
     */
    public LogRecord[] dequeue();
}
