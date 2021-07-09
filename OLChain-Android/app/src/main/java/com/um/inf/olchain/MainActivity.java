package com.um.inf.olchain;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;
import com.um.inf.olchain.olympus.BasicLocalIdPConfiguration;
import com.um.inf.olchain.olympus.ClientConfiguration;
import com.um.inf.olchain.olympus.ClientSingleton;
import com.um.inf.olchain.olympus.EncryptedCredentialStorage;
import com.um.inf.olchain.utils.Utils;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;


import android.util.Log;
import android.view.View;

import android.view.Menu;
import android.view.MenuItem;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Tap me, I do nothing :) ...", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });

        try {
            if(!ClientSingleton.isInitialized() && !Utils.secureSharedPreferences(getApplicationContext()).getString("vidp", "").equals("")) {
                tryInit();
            }
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void tryInit() {
        long start = System.nanoTime();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        CompletionService<Void> completionService = new ExecutorCompletionService<>(executor);
        EncryptedCredentialStorage encryptedCredentialStorage = new EncryptedCredentialStorage("credentialTest", getApplicationContext());
        InitializeCallable callable = new InitializeCallable(new BasicLocalIdPConfiguration(encryptedCredentialStorage), getApplicationContext());
        completionService.submit(callable);
        try {
            if (completionService.take().isDone() && ClientSingleton.isInitialized()) {
                Log.d("Main", "Initialization done");
            } else {
                Log.d("Main", "Initialization cancelled");
            }
        } catch (InterruptedException e) {
            //TODO Proper treatment
            Log.d("Main", "Could not initialize", e);
            throw new IllegalStateException("Could not initialize client");
        }
        double total = (System.nanoTime() - start) / 1_000_000_000.0;
        Log.d("TIME-AUTO-SETUP", "Setup time: " + total);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            Intent i = new Intent(this, SettingsActivity.class);
            startActivity(i);
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private static class InitializeCallable implements Callable<Void> {

        private ClientConfiguration config;
        private Context context;

        public InitializeCallable(ClientConfiguration config, Context context) {
            this.config = config;
            this.context = context;
        }

        @Override
        public Void call() throws Exception {
            try {
                ClientSingleton.initialize(config, context);
            } catch (Exception e) {
                Log.d("Initialize-Main", "Initialization exception", e);
                throw e;
            }
            return null;
        }
    }
}