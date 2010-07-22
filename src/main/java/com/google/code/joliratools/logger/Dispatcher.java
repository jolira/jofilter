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
import java.util.logging.Filter;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;

/**
 * @author jfk
 */
public final class Dispatcher extends Handler {
    static final int DEFAULT_QSIZE = 1024;

    /**
     * Copied from {@link LogManager}.
     * 
     * @see LogManager
     */
    private static Filter getFilterProperty(final String name, final Filter defaultValue) {
        final String val = getProperty(name);

        try {
            if (val != null) {
                final ClassLoader cl = ClassLoader.getSystemClassLoader();
                final Class<?> clz = cl.loadClass(val);

                return (Filter) clz.newInstance();
            }
        } catch (final Exception ex) {
            // We got one of a variety of exceptions in creating the
            // class or creating an instance.
            // Drop through.
        }
        // We got an exception. Return the defaultValue.
        return defaultValue;
    }

    /**
     * Copied from {@link LogManager}.
     * 
     * @see LogManager
     */
    private static Formatter getFormatterProperty(final String name, final Formatter defaultValue) {
        final String val = getProperty(name);
        try {
            if (val != null) {
                final ClassLoader cl = ClassLoader.getSystemClassLoader();
                final Class<?> clz = cl.loadClass(val);

                return (Formatter) clz.newInstance();
            }
        } catch (final Exception ex) {
            // We got one of a variety of exceptions in creating the
            // class or creating an instance.
            // Drop through.
        }
        // We got an exception. Return the defaultValue.
        return defaultValue;
    }

    /**
     * Copied from {@link LogManager}.
     * 
     * @see LogManager
     */
    private static int getIntProperty(final String name, final int defaultValue) {
        final String val = getProperty(name);

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
    private static Level getLevelProperty(final String name, final Level defaultValue) {
        final String val = getProperty(name);

        if (val == null) {
            return defaultValue;

        }
        try {
            return Level.parse(val.trim());
        } catch (final Exception ex) {
            return defaultValue;
        }
    }

    private static String getProperty(final String name) {
        final LogManager mgr = LogManager.getLogManager();

        return mgr.getProperty(name);
    }

    private final List<Reference<QImpl>> queues = new LinkedList<Reference<QImpl>>();
    private final int qsize;

    /**
     * Create a new instance.
     * 
     * @throws IllegalStateException
     *             if the dispatcher does not exist
     */
    public Dispatcher() {
        final String cname = getClass().getName();
        final Level level = getLevelProperty(cname + ".level", INFO);
        final Filter filter = getFilterProperty(cname + ".filter", null);
        final Formatter formatter = getFormatterProperty(cname + ".formatter", new SimpleFormatter());
        final String encoding = getProperty(cname + ".encoding");

        setLevel(level);
        setFilter(filter);
        setFormatter(formatter);
        setEncoding(encoding);

        qsize = getIntProperty(cname + ".qsize", DEFAULT_QSIZE);
    }

    @Override
    public void close() throws SecurityException {
        // nothing
    }

    /**
     * @return the newly created queue.
     */
    public Queue createQueue() {
        final QImpl q = new QImpl(qsize);
        final WeakReference<QImpl> reference = new WeakReference<QImpl>(q);

        synchronized (queues) {
            queues.add(reference);
        }

        return q;
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

    @Override
    public void setEncoding(final String encoding) {
        try {
            super.setEncoding(encoding);
        } catch (final Exception ex) {
            try {
                super.setEncoding(null);
            } catch (final Exception ex2) {
                // doing a setEncoding with null should always work.
                // assert false;
            }
        }
    }
}
