package com.google.code.joliratools.logger;

import java.util.logging.LogRecord;

public interface Queue {
    public LogRecord[] dequeue();
}
