package com.um.inf.olchain;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.StrictMode;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.um.inf.olchain.olympus.ClientSingleton;
import com.um.inf.olchain.rest.APIService;
import com.um.inf.olchain.rest.APIUtils;
import com.um.inf.olchain.rest.AsyncOperations;
import com.um.inf.olchain.rest.chainmodels.ChainPredicate;
import com.um.inf.olchain.rest.chainmodels.EndService;
import com.um.inf.olchain.rest.chainmodels.VerificationResult;
import com.um.inf.olchain.rest.chainmodels.VerifyQuery;
import com.um.inf.olchain.rest.signapimodels.ChainQuery;
import com.um.inf.olchain.services.ServiceListModel;
import com.um.inf.olchain.services.ServicesAdapter;
import com.um.inf.olchain.services.SignAPIPolicy;
import com.um.inf.olchain.utils.Utils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import VCModel.Verifiable;
import VCModel.VerifiablePresentation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.usecase.model.SignIdentityProof;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class ServicesFragment extends Fragment implements ServicesAdapter.OnServiceListener {
    /* Service List */
    private RecyclerView recyclerView;
    private ServicesAdapter adapter;
    private List<ServiceListModel> services;
    private LinkedHashMap<String, EndService> ledgerServices = new LinkedHashMap<>();
    private EndService serviceFromChain;

    private ProgressBar bar;

    private APIService apiService;

    @Override
    public View onCreateView(
            LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState
    ) {
        View view = inflater.inflate(R.layout.fragment_services, container, false);
        this.apiService = APIUtils.getAPIService();

        this.services = new LinkedList<>();
        recyclerView = view.findViewById(R.id.servicesListView);
        recyclerView.setLayoutManager(new LinearLayoutManager(view.getContext()));

        adapter = new ServicesAdapter(services, this);
        recyclerView.setHasFixedSize(true);
        recyclerView.setAdapter(adapter);

        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);

        bar = view.findViewById(R.id.progressBar);

        getAvailableServices();
        autoSignUp();

        return view;
    }

    public void onViewCreated(@NonNull View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
    }

    @Override
    public void onClick(int index) {
        long start = System.nanoTime();
        ServiceListModel service = this.services.get(index);
        if(service != null) {
            if(!comparePredicates(index)) {
                AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
                builder.setTitle(R.string.warning).setMessage(R.string.warning_msg).setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
                        builder.setTitle(R.string.askPermissions).setMessage(service.policySummary()).setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                Policy policy = getPolicy(index);
                                bar.setVisibility(View.VISIBLE);
                                if(ClientSingleton.getCredentialManager().checkStoredCredential()) {
                                    long startFromStorage = System.nanoTime();
                                    VerifiablePresentation vp = ClientSingleton.getCredentialManager().generatePresentationToken(policy);
                                    double totalStorage = (System.nanoTime() - startFromStorage) / 1_000_000_000.0;
                                    Log.d("TIME-FROM-STORAGE", totalStorage + " seconds");
                                    Log.d("Authentication from storage", vp.toJSONString());
                                    verifyToken(vp.toJSONString(), policy, start);
                                    bar.setVisibility(View.GONE);
                                } else {
                                    doLogin(policy, start);
                                }
                                dialog.dismiss();
                            }
                        }).setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                dialog.dismiss();
                            }
                        });
                        builder.create().show();
                    }
                }).setNeutralButton("Report", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        sendEventToLedger(ledgerServices.get(Utils.serviceIdForIndex(index)).getDid().getId());
                    }
                });
                builder.create().show();
            } else {
                AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
                builder.setTitle(R.string.askPermissions).setMessage(service.policySummary()).setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        Policy p = getPolicy(index);
                        bar.setVisibility(View.VISIBLE);
                        if(ClientSingleton.getCredentialManager().checkStoredCredential()) {
                            long startFromStorage = System.nanoTime();
                            VerifiablePresentation vp = ClientSingleton.getCredentialManager().generatePresentationToken(p);
                            double totalStorage = (System.nanoTime() - startFromStorage) / 1_000_000_000.0;
                            Log.d("TIME-FROM-STORAGE", totalStorage + " seconds");
                            Log.d("Authentication from storage", vp.toJSONString());
                            verifyToken(vp.toJSONString(), p, start);
                            bar.setVisibility(View.GONE);
                        } else {
                            doLogin(p, start);
                        }
                        dialog.dismiss();
                    }
                }).setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                });
                builder.create().show();
            }
        }
    }

    private Policy getPolicy(int index) {
        Policy policy = new Policy();
        List<Predicate> listP = new LinkedList<>();
        Predicate predicate = null;
        for(SignAPIPolicy sp: services.get(index).getPolicy()) {
            predicate = new Predicate();
            predicate.setOperation(sp.getOlympusOperation());
            predicate.setAttributeName(sp.getAttributeName());
            if(sp.getValue() != null) {
                predicate.setValue(sp.getValue().getOlympusAttribute());
            }
            if(sp.getExtra() != null) {
                predicate.setExtraValue(sp.getExtra().getOlympusAttribute());
            }
            listP.add(predicate);
        }
        policy.setPredicates(listP);
        policy.setPolicyId("OLYMPUS-POLICY" + ThreadLocalRandom.current().nextInt());
        return policy;
    }

    private void getAvailableServices() {
        apiService.getServices().enqueue(new Callback<List<ServiceListModel>>() {
            @Override
            public void onResponse(Call<List<ServiceListModel>> call, Response<List<ServiceListModel>> response) {
                services.addAll(response.body());

                if(ledgerServices.isEmpty()) {
                    for(int i = 0; i<services.size(); i++) {
                        getServiceFromLedger(Utils.serviceIdForIndex(i), i);
                    }
                }
                adapter.notifyDataSetChanged();
            }
            @Override
            public void onFailure(Call<List<ServiceListModel>> call, Throwable t) {
                System.out.println("Error" + t.getMessage());
            }
        });
    }

    public void doLogin(Policy p, long time) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            Log.d("Policy", mapper.writeValueAsString(p));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        AsyncOperations operations = new AsyncOperations() {
            @Override
            public void handleRegisterResponse(Object response) {}
            @Override
            public void handleLoginResponse(Object response) {
                if(response instanceof Exception) {
                    Log.e("Authentication", "Exception");
                } else if (response.equals("Failed")) {
                    Log.e("Authentication", "Failed");
                } else {
                    Log.d("Authentication", "Success");
                    Log.d("Check Storage", ClientSingleton.getCredentialManager().checkStoredCredential()+"");
                    Log.d("Authentication", response.toString());

                    VerifiablePresentation vp = new VerifiablePresentation(Verifiable.getJSONMap(response.toString()));
                    verifyToken(vp.toJSONString(), p, time);
                }
            }
        };
        operations.doAsyncLogin(Utils.getLoginUsr(getContext()), Utils.getLoginPwd(getContext()), p);
        // TODO 1. Do login; 2. Directly run OL Token obtaining to open service
    }

    public void doSignUp() {

        SignIdentityProof proof = Utils.getUsrAttr(getContext());
        AsyncOperations operations = new AsyncOperations() {
            @Override
            public void handleRegisterResponse(Object response) {
                Log.d("Register", response.toString());
                if (response.toString().equals("Sign up done")) {
                    try {
                        Utils.secureSharedPreferences(getContext()).edit().putString("registered", "true").apply();
                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                } else if (response.toString().contains("UserCreationFailedException")) {
                    Log.d("Register", "User already exists");
                    try {
                        Utils.secureSharedPreferences(getContext()).edit().putString("registered", "true").apply();
                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }

            @Override
            public void handleLoginResponse(Object response) {
                Log.d("Login", response.toString());
            }
        };
        try {
            operations.doAsyncRegister(Utils.getLoginUsr(getContext()), Utils.getLoginPwd(getContext()), proof);
        } catch (Exception e) {
            Log.e("CLIENT STATUS", "" + ClientSingleton.isInitialized());
        }
    }

    private void autoSignUp() {
        try {
            if (Utils.secureSharedPreferences(getContext()).getString("registered", "").isEmpty() &&
                    Utils.secureSharedPreferences(getContext()).getString("external", "").equals("true")) {
                doSignUp();

                int duration = Toast.LENGTH_LONG;
                Toast toast = Toast.makeText(getContext(), "Sign-up successful", duration);
                toast.show();

            } else {
                Log.d("AUTO-SIGNUP", "User already registered");
            }
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void getServiceFromLedger(String serviceId, int index) {
        ChainQuery query = new ChainQuery("", "", serviceId, "", "", "");
        apiService.getLedgerService(query).enqueue(new Callback<EndService>() {
            @Override
            public void onResponse(Call<EndService> call, Response<EndService> response) {
                ledgerServices.put(serviceId, response.body());
                services.get(index).setLedgerPolicyCoincidence(comparePredicates2(response.body(), index));
                adapter.notifyDataSetChanged();
                Log.d("SERVICES-LEDGER", "added: "+  serviceId +" Total: " + ledgerServices.size());
            }

            @Override
            public void onFailure(Call<EndService> call, Throwable t) {
                Log.e("SERVICES-LEDGER", "FETCH ERROR" + t.getMessage());
            }
        });

    }

    private void sendEventToLedger(String did) {
        ChainQuery query = new ChainQuery("", "", "", did, "Policy conflict", "REPORT");
        try {
            if (apiService.sendEventToLedger(query).execute().isSuccessful()) {
                Toast.makeText(getContext(), "Thanks for your help!", Toast.LENGTH_SHORT).show();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            bar.setVisibility(View.GONE);
        }
    }

    private boolean verifyToken(String vp, Policy policy, long time) {
        long start = System.nanoTime();
        try {
            String did = Utils.secureSharedPreferences(getContext()).getString("vidp-name", "");
            VerifyQuery query = new VerifyQuery(did, vp, policy);
            Log.d("VERF-QUERY", new Gson().toJson(query));
            apiService.verifyToken(query).enqueue(new Callback<VerificationResult>() {
                @Override
                public void onResponse(Call<VerificationResult> call, Response<VerificationResult> response) {
                    Log.d("Verify", response.body().getVerificationResult().toString());
                    Intent i = null;
                    if(response.body().getVerificationResult()) {
                        i = new Intent(getContext(), SuccessActivity.class);
                        i.putExtra("vp", vp);
                    } else {
                       i = new Intent(getContext(), ErrorActivity.class);
                    }
                    double total = (System.nanoTime() - start) / 1_000_000_000.0;
                    Log.d("TIME-VERIFY", "Verify time: " + total);
                    double total2 = (System.nanoTime() - time) / 1_000_000_000.0;
                    Log.d("TIME-VERIFY-SINCE-CLICK", "Full verify time: " + total2);
                    startActivity(i);
                }

                @Override
                public void onFailure(Call<VerificationResult> call, Throwable t) {
                    Log.d("Verify-ERROR", t.getMessage());
                }
            });

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    private boolean comparePredicates2(EndService ledger, int index) {
        long start = System.nanoTime();
        Policy policy = getPolicy(index);
        List<ChainPredicate> ledgerList = new LinkedList<>();
        ledgerList.addAll(ledger.getPredicates());
        List<Predicate> list2 = policy.getPredicates();
        if (list2.size() != ledgerList.size()) {
            // Different number of predicates
            double total = (System.nanoTime() - start) / 1_000_000_000.0;
            Log.d("TIME-COMPARE-PREDICATES", "Compare time: " + total);
            return false;
        } else {
            for (Predicate p : list2) {
                for (ChainPredicate cp : ledgerList) {
                    if (cp.getAttributeName().equals(p.getAttributeName())) {
                        if (!cp.getOperation().equals(p.getOperation().name())) {
                            double total = (System.nanoTime() - start) / 1_000_000_000.0;
                            Log.d("TIME-COMPARE-PREDICATES", "Compare time: " + total);
                            // Operation changed
                            return false;
                        } else {
                            if (cp.getValue() != null && p.getValue() != null) {
                                if (!cp.getValue().equals(p.getValue().toString())) {
                                    // Value has been modified
                                    double total = (System.nanoTime() - start) / 1_000_000_000.0;
                                    Log.d("TIME-COMPARE-PREDICATES", "Compare time: " + total);
                                    return false;
                                } else {
                                    if ((cp.getExtraValue() != null && p.getExtraValue() == null) ||
                                            (cp.getExtraValue() != null && p.getExtraValue() != null) &&
                                                    (!cp.getExtraValue().equals(p.getExtraValue().toString()))) {
                                        // Extra Value has been modified
                                        double total = (System.nanoTime() - start) / 1_000_000_000.0;
                                        Log.d("TIME-COMPARE-PREDICATES", "Compare time: " + total);
                                        return false;
                                    }
                                }
                            } else if ((cp.getValue() != null && p.getValue() == null) || (cp.getValue() == null && p.getValue() != null)) {
                                // Value has been changed
                                double total = (System.nanoTime() - start) / 1_000_000_000.0;
                                Log.d("TIME-COMPARE-PREDICATES", "Compare time: " + total);
                                return false;
                            }
                        }
                    }
                }
            }
        }
        double total = (System.nanoTime() - start) / 1_000_000_000.0;
        Log.d("TIME-COMPARE-PREDICATES", "Compare time: " + total);
        return true;
    }

    private boolean comparePredicates(int index) {
        Policy policy = getPolicy(index);
        List<ChainPredicate> ledgerList = new LinkedList<>();
        if (this.ledgerServices.get(Utils.serviceIdForIndex(index)) == null) return false;
        ledgerList.addAll(this.ledgerServices.get(Utils.serviceIdForIndex(index)).getPredicates());
        List<Predicate> list2 = policy.getPredicates();
        if (list2.size() != ledgerList.size()) {
            // Different number of predicates
            return false;
        } else {
            for (Predicate p : list2) {
                for (ChainPredicate cp : ledgerList) {
                    if (cp.getAttributeName().equals(p.getAttributeName())) {
                        if (!cp.getOperation().equals(p.getOperation().name())) {
                            // Operation changed
                            return false;
                        } else {
                            if (cp.getValue() != null && p.getValue() != null) {
                                if (!cp.getValue().equals(p.getValue().toString())) {
                                    // Value has been modified
                                    return false;
                                } else {
                                    if ((cp.getExtraValue() != null && p.getExtraValue() == null) ||
                                            (cp.getExtraValue() != null && p.getExtraValue() != null) &&
                                                    (!cp.getExtraValue().equals(p.getExtraValue().toString()))) {
                                        // Extra Value has been modified
                                        return false;
                                    }
                                }
                            } else if ((cp.getValue() != null && p.getValue() == null) || (cp.getValue() == null && p.getValue() != null)) {
                                // Value has been changed
                                return false;
                            }
                        }
                    }
                }
            }
        }
        return true;
    }
}