package com.um.inf.olchain;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Switch;

import com.google.gson.Gson;
import com.um.inf.olchain.rest.APIService;
import com.um.inf.olchain.rest.APIUtils;
import com.um.inf.olchain.rest.chainmodels.Vidp;
import com.um.inf.olchain.rest.signapimodels.SignedAttributes;
import com.um.inf.olchain.utils.Utils;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import eu.olympus.usecase.model.SignIdentityProof;
import eu.olympus.usecase.model.USCAttributes;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class SettingsActivity extends AppCompatActivity implements AdapterView.OnItemSelectedListener {

    private EditText usrLogin;
    private EditText usrPassword;
    private EditText usrSignUpLogin;
    private EditText usrSignUpPassword;
    private Switch externalSources;
    private Button saveButton;
    private Spinner settingsSpinner;
    private ArrayAdapter<String> spinnerAdapter = null;

    private List<Vidp> vidps = new LinkedList<>();
    ArrayList<String> vidpsNames = null;
    private Vidp selected;

    private APIService apiService;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        // Get an API instance
        apiService = APIUtils.getAPIService();

        this.usrLogin = findViewById(R.id.editTextUser);
        this.usrPassword = findViewById(R.id.editTextPassword);
        this.usrSignUpLogin = findViewById(R.id.editTextUser2);
        this.usrSignUpPassword = findViewById(R.id.editTextTextPassword2);
        this.externalSources = findViewById(R.id.switchExternalSource);
        this.saveButton = findViewById(R.id.saveButton);
        this.settingsSpinner = findViewById(R.id.settingsSpinner);

        settingsSpinner.setOnItemSelectedListener(this);

        getClientParametersFromLedger();
        loadPrefs();

    }

    private void loadPrefs() {
        if(!this.usrLogin.getText().equals("") && !this.usrPassword.getText().equals("")) {
            try {
                this.usrLogin.setText(Utils.secureSharedPreferences(getApplicationContext()).getString("usr", ""));
                this.usrPassword.setText(Utils.secureSharedPreferences(getApplicationContext()).getString("pwd", ""));
                this.usrSignUpLogin.setText(Utils.secureSharedPreferences(getApplicationContext()).getString("usr", ""));
                this.usrSignUpPassword.setText(Utils.secureSharedPreferences(getApplicationContext()).getString("pwd", ""));
                if(Utils.secureSharedPreferences(getApplicationContext()).getString("external", "").equals("true")) {
                    this.externalSources.setChecked(true);
                    String usrAttrs = Utils.secureSharedPreferences(getApplicationContext()).getString("Attributes", "");
                    Log.d("Attributes", usrAttrs);
                } else this.externalSources.setChecked(false);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if(!this.usrSignUpLogin.getText().equals("") && !this.usrSignUpPassword.getText().equals("")) {
            try {
                this.usrLogin.setText(Utils.secureSharedPreferences(getApplicationContext()).getString("usr2", ""));
                this.usrPassword.setText(Utils.secureSharedPreferences(getApplicationContext()).getString("pwd2", ""));
                this.usrSignUpLogin.setText(Utils.secureSharedPreferences(getApplicationContext()).getString("usr2", ""));
                this.usrSignUpPassword.setText(Utils.secureSharedPreferences(getApplicationContext()).getString("pwd2", ""));
                if(Utils.secureSharedPreferences(getApplicationContext()).getString("external", "").equals("true")) {
                    this.externalSources.setChecked(true);
                } else this.externalSources.setChecked(false);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void savePrefs(View v) {
        try {
            if (this.selected != null) {
                Gson gson = new Gson();
                Utils.secureSharedPreferences(getApplicationContext()).edit().putString("vidp", gson.toJson(selected)).apply();
                Utils.secureSharedPreferences(getApplicationContext()).edit().putString("vidp-name", selected.getDid().getId()).apply();
                Utils.secureSharedPreferences(getApplicationContext()).edit().putString("vidp-index", String.valueOf(settingsSpinner.getSelectedItemPosition())).apply();
            }
            if(this.externalSources.isChecked()) {
                Utils.secureSharedPreferences(getApplicationContext()).edit().putString("external", "true").apply();
                getAttributes();
            } else {
                Utils.secureSharedPreferences(getApplicationContext()).edit().putString("external", "false").apply();
            }
            if(!this.usrLogin.getText().equals("") && !this.usrPassword.getText().equals("")) {
                Utils.secureSharedPreferences(getApplicationContext()).edit().putString("usr", this.usrLogin.getText().toString()).apply();
                Utils.secureSharedPreferences(getApplicationContext()).edit().putString("pwd", this.usrPassword.getText().toString()).apply();
            }
            if(!this.usrSignUpLogin.getText().equals("") && !this.usrSignUpPassword.getText().equals("")) {
                Utils.secureSharedPreferences(getApplicationContext()).edit().putString("usr2", this.usrSignUpLogin.getText().toString()).apply();
                Utils.secureSharedPreferences(getApplicationContext()).edit().putString("pwd2", this.usrSignUpPassword.getText().toString()).apply();

                Utils.secureSharedPreferences(getApplicationContext()).edit().putString("usr", this.usrSignUpLogin.getText().toString()).apply();
                Utils.secureSharedPreferences(getApplicationContext()).edit().putString("pwd", this.usrSignUpPassword.getText().toString()).apply();
            }
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void getAttributes() {
        apiService.bchainAttrs().enqueue(new Callback<SignedAttributes>() {
            @Override
            public void onResponse(Call<SignedAttributes> call, Response<SignedAttributes> response) {
                Log.d("TEST", "" + response.body());
                Gson gson = new Gson();
                try {
                    Utils.secureSharedPreferences(getApplicationContext()).edit().putString("Attributes", gson.toJson(response.body())).apply();
                    Log.d("Get attributes", gson.toJson(response.body()));
                } catch (GeneralSecurityException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void onFailure(Call<SignedAttributes> call, Throwable t) {
                Log.e("Get attributes", "ERROR");
            }
        });
    }

    private void getClientParametersFromLedger() {
        apiService.getLedgerVidp(1).enqueue(new Callback<List<Vidp>>() {
            @Override
            public void onResponse(Call<List<Vidp>> call, Response<List<Vidp>> response) {
                vidps = response.body();
                if(vidps != null) {
                    vidpsNames = new ArrayList<>();
                    for(Vidp v: vidps) {
                        vidpsNames.add(v.getDid().getId());
                    }
                    spinnerAdapter = new ArrayAdapter<>(getApplicationContext(), android.R.layout.simple_spinner_item, vidpsNames);
                    settingsSpinner.setAdapter(spinnerAdapter);

                    try {
                        if(Utils.secureSharedPreferences(getApplicationContext()).getString("vidp-index", "") != "" && !vidpsNames.isEmpty()) {
                            settingsSpinner.setSelection(Integer.valueOf(Utils.secureSharedPreferences(getApplicationContext()).getString("vidp-index", "")));
                        }
                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }

            @Override
            public void onFailure(Call<List<Vidp>> call, Throwable t) {
                Log.e("Ledger vIdP parameters", "Error getting vIdP");
            }
        });
    }

    @Override
    public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {
        this.selected = vidps.get(settingsSpinner.getSelectedItemPosition());
        Log.d("Spinner", "vIdP: " + vidps.get(settingsSpinner.getSelectedItemPosition()).getDid().getId());
    }

    @Override
    public void onNothingSelected(AdapterView<?> adapterView) {
        Log.d("Spinner", "POS: " + settingsSpinner.getSelectedItemPosition());
    }
}