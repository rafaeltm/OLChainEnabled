package com.um.inf.olchain.rest;

import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;

import androidx.annotation.NonNull;

import com.um.inf.olchain.olympus.ClientSingleton;

import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;

public abstract class AsyncOperations {
    private static final String TAG = AsyncOperations.class.getSimpleName();
    public static final String SIGNUP_OK="Sign up done";

    public void doAsyncLogin(String user, String password, Policy policy) {
        HandlerThread ht = AsyncHandler.getInstance().getHandler();
        ht.start();
        Handler asyncHandler = new Handler(ht.getLooper()) {
            @Override
            public void handleMessage(@NonNull Message msg) {
                super.handleMessage(msg);
                handleLoginResponse(msg.obj);
            }
        };
        Runnable runnable = () -> {
            try {
                ClientSingleton.getInstance().clearSession();
                String res = ClientSingleton.getInstance().authenticate(user, password, policy, null, "NONE");
                Message message = new Message();
                message.obj = res;
                asyncHandler.sendMessage(message);
            } catch (AuthenticationFailedException e) {
                Message message = new Message();
                message.obj = e;
                asyncHandler.sendMessage(message);
            }
        };
        asyncHandler.post(runnable);
    }

    public void doAsyncRegister(String user, String password, IdentityProof proof) {
        HandlerThread ht = AsyncHandler.getInstance().getHandler();
        ht.start();
        Handler asyncHandler = new Handler(ht.getLooper()) {
            @Override
            public void handleMessage(@NonNull Message msg) {
                super.handleMessage(msg);
                handleRegisterResponse(msg.obj);
            }
        };
        Runnable runnable = () -> {
            try {
                ClientSingleton.getInstance().createUser(user, password);
                if (proof != null) {
                    ClientSingleton.getInstance().addAttributes(user, password, proof, null, "NONE");
                }
                Message message = new Message();
                message.obj = SIGNUP_OK;
                asyncHandler.sendMessage(message);
            } catch (UserCreationFailedException e) {
                Message message = new Message();
                message.obj = e;
                asyncHandler.sendMessage(message);
            } catch (AuthenticationFailedException e) {
                e.printStackTrace();
            }
        };
        asyncHandler.post(runnable);
    }
    public abstract void handleRegisterResponse(Object response);
    public abstract void handleLoginResponse(Object response);
}