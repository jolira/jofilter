/**
 * 
 */
package com.google.code.joliratools.logger;

import static java.util.logging.Level.INFO;

import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;

/**
 * @author jfk
 * 
 */
public final class Dispatcher extends Handler {
    static final int DEFAULT_QSIZE = 1024;

    private static int getIntProperty(final String name, final int defaultValue) {
        final LogManager mgr = LogManager.getLogManager();
        final String val = mgr.getProperty(name);

        if (val == null) {
            return defaultValue;

        }
        try {
            return Integer.parseInt(val);
        } catch (final Exception ex) {
            return defaultValue;
        }
    }

    /**
     * Copied from {@link LogManager}.
     * 
     * @see LogManager
     */
    private static Level getLevelProperty(final String name,
            final Level defaultValue) {
        final LogManager mgr = LogManager.getLogManager();
        final String val = mgr.getProperty(name);

        if (val == null) {
            return defaultValue;

        }
        try {
            return Level.parse(val.trim());
        } catch (final Exception ex) {
            return defaultValue;
        }
    }

    private final List<Reference<QImpl>> queues = new LinkedList<Reference<QImpl>>();
    private final int qsize;

    public Dispatcher() {
        final String cname = getClass().getName();
        final Level level = getLevelProperty(cname + ".level", INFO);

        setLevel(level);

        qsize = getIntProperty(cname + ".qsize", DEFAULT_QSIZE);
    }

    public Queue addQueue() {
        final QImpl q = new QImpl(qsize);
        final WeakReference<QImpl> reference = new WeakReference<QImpl>(q);

        synchronized (queues) {
            queues.add(reference);
        }

        return q;
    }

    @Override
    public void close() throws SecurityException {
        // nothing
    }

    @Override
    public void flush() {
        // nothing
    }

    private QImpl[] getSubscribers() {
        synchronized (queues) {
            final int size = queues.size();
            final Collection<QImpl> _queues = new ArrayList<QImpl>(size);

            for (int idx = 0; idx < queues.size();) {
                final Reference<QImpl> reference = queues.get(idx);
                final QImpl queue = reference.get();

                if (queue != null) {
                    _queues.add(queue);
                    idx++;
                } else {
                    queues.remove(idx);
                }
            }

            final int _size = _queues.size();

            return _queues.toArray(new QImpl[_size]);
        }

    }

    @Override
    public void publish(final LogRecord record) {
        final QImpl[] _queues = getSubscribers();

        for (final QImpl q : _queues) {
            q.enqueue(record);
        }
    }
}
