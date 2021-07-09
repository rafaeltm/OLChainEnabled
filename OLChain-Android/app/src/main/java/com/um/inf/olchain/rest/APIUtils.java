package com.um.inf.olchain.rest;


public class APIUtils {
    // TODO: SET OLYMPUS ENDPOINT
    public static final String BASE_URL = "http://10.0.2.2:3000";

    public static APIService getAPIService() {
        return RetrofitClient.getClient(BASE_URL).create(APIService.class);
    }
}