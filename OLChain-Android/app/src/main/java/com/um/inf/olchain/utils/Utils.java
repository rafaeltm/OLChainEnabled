package com.um.inf.olchain.utils;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.util.Log;

import androidx.security.crypto.EncryptedFile;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKeys;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.um.inf.olchain.rest.signapimodels.SignedAttributes;
import com.um.inf.olchain.services.SignAPIPolicy;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.usecase.model.SignIdentityProof;
import eu.olympus.usecase.model.USCAttributes;
import eu.olympus.util.Util;

public class Utils {
    public static final String formatRFC3339UTC = "yyyy-MM-dd'T'HH:mm:ss";

    // Encrypted sharedPreferences
    public static SharedPreferences secureSharedPreferences(Context context) throws GeneralSecurityException, IOException {
        SharedPreferences sharedPreferences = EncryptedSharedPreferences.create(
                "accountData",
                "Vgkq3lirFC", // Random
                context,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );

        return sharedPreferences;
    }

    // Encrypted file read
    public static byte[] readEncrypted(String fileToRead, Context context) throws GeneralSecurityException, IOException {
        // Although you can define your own key generation parameter specification, it's
        // recommended that you use the value specified here.
        KeyGenParameterSpec keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC;
        String masterKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec);

        File credFile = new File(context.getFilesDir(), fileToRead);
        EncryptedFile encryptedFile = new EncryptedFile.Builder(
                credFile,
                context,
                masterKeyAlias,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build();

        InputStream inputStream = encryptedFile.openFileInput();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int nextByte = inputStream.read();
        while (nextByte != -1) {
            byteArrayOutputStream.write(nextByte);
            nextByte = inputStream.read();
        }


        return byteArrayOutputStream.toByteArray();
    }

    // Encrypted file write
    public static void writeEncrypted(String fileToWrite, byte[] fileContent, Context context) {
        try {
            // Although you can define your own key generation parameter specification, it's
            // recommended that you use the value specified here.
            KeyGenParameterSpec keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC;
            String masterKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec);

            // Creates a file with this name, or replaces an existing file
            // that has the same name. Note that the file name cannot contain
            // path separators.
            File credFile = new File(context.getFilesDir(), fileToWrite);
            if (credFile.exists()) {
                credFile.delete();
            }
            EncryptedFile encryptedFile = new EncryptedFile.Builder(
                    credFile,
                    context,
                    masterKeyAlias,
                    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build();

            OutputStream outputStream = encryptedFile.openFileOutput();
            outputStream.write(fileContent);
            outputStream.flush();
            outputStream.close();
        } catch (GeneralSecurityException e) {
            Log.d("UTILS", "Write file", e);
        } catch (IOException e) {
            Log.d("UTILS", "Write file", e);
        }
    }

    public static Policy policyFromJsonString(List<SignAPIPolicy> pp) {
        Policy policy = new Policy();
        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate;
        for (SignAPIPolicy p: pp) {
            predicate = new Predicate();
            predicate.setAttributeName(p.getAttributeName());
            predicate.setOperation(p.getOlympusOperation());
            // TODO AUTOMATED DESERIALIZE
            predicates.add(predicate);
        }
        policy.setPredicates(predicates);
        return policy;
    }
    public static String serviceIdForIndex(int index) {
        switch (index) {
            case 0:
                return "servicioimpresion";
            case 1:
                return "citaprevia";
            case 2:
                return "actas";
            case 3:
                return "reservasalaestudio";
            case 4:
                return "serviciobecas";
            default:
                return "servicioimpresion";
        }
    }

    public static SimpleDateFormat getDateFormatRFC3339UTC() {
        SimpleDateFormat dateFormatRFC3339UTC = new SimpleDateFormat(formatRFC3339UTC);
        dateFormatRFC3339UTC.setTimeZone(TimeZone.getTimeZone("UTC"));
        return dateFormatRFC3339UTC;
    }

    public static String toRFC3339UTC(Date date) {
        return getDateFormatRFC3339UTC().format(date);
    }

    public static Date fromRFC3339UTC(String str) {
        try {
            return getDateFormatRFC3339UTC().parse(str);
        }
        catch (ParseException e) {
            return null;
        }
    }

    public static String getLoginUsr(Context c) {
        try {
            return Utils.secureSharedPreferences(c).getString("usr", "");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }

    public static String getLoginPwd(Context c) {
        try {
            return Utils.secureSharedPreferences(c).getString("pwd", "");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }

    public static SignIdentityProof getUsrAttr(Context c) {
        SignIdentityProof proof = null;
        SignedAttributes pp = null;
        try {
            String json = Utils.secureSharedPreferences(c).getString("Attributes", "");
            Gson gson = new Gson();
            pp = gson.fromJson(json, SignedAttributes.class);
            proof = new SignIdentityProof();
            proof.setSignature(pp.getSignature());
            proof.setData(new USCAttributes(pp.getData().getUrlOrganization(), pp.getData().getUrlDateOfBirth(), pp.getData().getUrlMail(), pp.getData().getUrlRole(), pp.getData().getUrlAnnualSalary()));
            Log.d("JSON", proof.getStringRepresentation());
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return proof;
    }
}
