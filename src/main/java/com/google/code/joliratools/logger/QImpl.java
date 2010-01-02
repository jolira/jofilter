package com.google.code.joliratools.logger;

import java.util.LinkedList;
import java.util.logging.LogRecord;

final class QImpl implements Queue {
    private final LinkedList<LogRecord> q = new LinkedList<LogRecord>();
    private final int qsize;

    QImpl(final int qsize) {
        this.qsize = qsize;
    }

    @Override
    public LogRecord[] dequeue() {
        LogRecord[] records;

        synchronized (q) {
            final int size = q.size();

            records = q.toArray(new LogRecord[size]);

            q.clear();
        }
        return records;
    }

    void enqueue(final LogRecord record) {
        synchronized (q) {
            final int size = q.size();

            if (size >= qsize) {
                q.removeFirst();
            }
        }

        q.addLast(record);
    }
}
