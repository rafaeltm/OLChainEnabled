package com.um.inf.olchain.rest;

import com.um.inf.olchain.rest.chainmodels.EndService;
import com.um.inf.olchain.rest.chainmodels.PublicParamsLedger;
import com.um.inf.olchain.rest.chainmodels.VerificationResult;
import com.um.inf.olchain.rest.chainmodels.VerifyQuery;
import com.um.inf.olchain.rest.chainmodels.Vidp;
import com.um.inf.olchain.rest.signapimodels.ChainQuery;
import com.um.inf.olchain.rest.signapimodels.SignedAttributes;
import com.um.inf.olchain.services.ServiceListModel;

import java.util.List;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.Headers;
import retrofit2.http.POST;
import retrofit2.http.Query;

public interface APIService {
    @Headers("Content-Type: application/json")
    @GET("/sign/bchainAttrs")
    Call<SignedAttributes> bchainAttrs();

    @Headers("Content-Type: application/json")
    @GET("/services")
    Call<List<ServiceListModel>> getServices();

    @Headers("Content-Type: application/json")
    @POST("/chain/getvidp")
    Call<Vidp> getLedgerVidp(@Body ChainQuery query);

    @Headers("Content-Type: application/json")
    @GET("/chain/getvidp")
    Call<List<Vidp>> getLedgerVidp(@Query("active") int active);

    @Headers("Content-Type: application/json")
    @POST("/chain/getschema")
    Call<PublicParamsLedger> getLedgerSchema(@Body ChainQuery query);

    @Headers("Content-Type: application/json")
    @GET("/chain/getservices")
    Call<List<EndService>> getLedgerServices(@Query("active") int active);

    @Headers("Content-Type: application/json")
    @POST("/chain/getservice")
    Call<EndService> getLedgerService(@Body ChainQuery query);

    @Headers("Content-Type: application/json")
    @POST("/chain/sendevent")
    Call<Void> sendEventToLedger(@Body ChainQuery query);

    @Headers("Content-Type: application/json")
    @POST("/olverifier/verifypresentation")
    Call<VerificationResult> verifyToken(@Body VerifyQuery query);

}