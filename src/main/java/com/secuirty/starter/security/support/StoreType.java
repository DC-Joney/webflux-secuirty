package com.secuirty.starter.security.support;

public enum StoreType {

    /**
     * Redis backed sessions.
     */
    REDIS,

    /**
     * JDBC backed sessions.
     */
    JDBC,

    /**
     * No session data-store.
     */
    INMEMORY

}