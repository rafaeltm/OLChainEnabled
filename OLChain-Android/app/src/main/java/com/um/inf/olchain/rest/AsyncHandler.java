package com.um.inf.olchain.rest;

import android.os.HandlerThread;

public class AsyncHandler {
    private static AsyncHandler asyncHandler;
    private HandlerThread handler;

    private AsyncHandler() {
        handler = new HandlerThread("AsyncHandlerThread");
    }

    public static AsyncHandler getInstance() {
        if (asyncHandler == null) {
            return  new AsyncHandler();
        }
        return asyncHandler;
    }

    public HandlerThread getHandler() {
        return handler;
    }
}