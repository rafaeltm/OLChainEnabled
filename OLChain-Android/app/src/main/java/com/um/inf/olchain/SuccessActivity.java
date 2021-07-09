package com.um.inf.olchain;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

import VCModel.Proof;
import VCModel.Verifiable;
import VCModel.VerifiablePresentation;

public class SuccessActivity extends AppCompatActivity {

    private TextView vp1;
    private TextView vp2;
    private TextView vp3;
    private TextView vp4;

    private VerifiablePresentation vp;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_success);

        vp1 = findViewById(R.id.vp1);
        vp2 = findViewById(R.id.vp2);
        vp3 = findViewById(R.id.vp3);
        vp4 = findViewById(R.id.vp4);

        Bundle bundle = getIntent().getExtras();
        if(bundle != null) {
            this.vp = new VerifiablePresentation(Verifiable.getJSONMap(bundle.getString("vp")));

            //vp1.setText("VP-ID: " + vp.getId());
            vp2.setText("VP-Expiration date: " + vp.getExpirationDate());
            vp3.setText("VP-Context: " + vp.getContext());
            //vp4.setText("VP-Proof: " + vp.getProof());
        }

    }
}