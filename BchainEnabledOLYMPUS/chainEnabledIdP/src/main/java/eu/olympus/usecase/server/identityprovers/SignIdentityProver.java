package eu.olympus.usecase.server.identityprovers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.model.Attribute;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.usecase.model.SignIdentityProof;
import eu.olympus.util.Util;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

public class SignIdentityProver implements IdentityProver {
    private Storage storage;

    public SignIdentityProver(Storage storage) throws Exception {
        this.storage = storage;
    }

    @Override
    public boolean isValid(String idProof, String username) {
       long startTime = System.nanoTime();
        // Check idproof data signature http://localhost:3000/sign/verify
        try {
            JSONParser parser = new JSONParser();
            net.minidev.json.JSONObject iProofJson = (net.minidev.json.JSONObject) parser.parse(idProof);
            SignIdentityProof obj = new SignIdentityProof(iProofJson);

            HttpClient httpClient = HttpClientBuilder.create().build(); //Use this instead
            String json = "";
            ObjectMapper mapper = new ObjectMapper();
            try {
                json = mapper.writeValueAsString(obj);
            } catch (JsonMappingException e) {
                e.printStackTrace();
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }

            // TODO Change URL to API when necessary
            HttpPost request = new HttpPost("http://localhost:3000/sign/verify");
            StringEntity params =new StringEntity(json);
            request.addHeader("content-type", "application/json");
            request.setEntity(params);
            HttpResponse response = httpClient.execute(request);

            if(response.getEntity().getContentLength() != 0) {
                StringBuilder sb = new StringBuilder();
                BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()), 65728);
                String line = null;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }

                JSONObject resp = new JSONObject(sb.toString());
                long duration = (System.nanoTime() - startTime);
                System.err.println("Signature verf time: " + duration);
                System.out.println("RESULT: " + resp.get("signature_status"));
                return (boolean)resp.get("signature_status");
            }

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (ClientProtocolException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public void addAttributes(String proof, String username) {
        SignIdentityProof obj = getProof(proof);
        if(obj != null) {
            Map<String, Attribute> proverAttributes = new HashMap<>();
            proverAttributes.put("url:DateOfBirth", new Attribute(Util.fromRFC3339UTC(obj.getData().getDateOfBirth())));
            proverAttributes.put("url:Mail", new Attribute(obj.getData().getMail()));
            proverAttributes.put("url:Organization", new Attribute(obj.getData().getOrganization()));
            proverAttributes.put("url:Role", new Attribute(obj.getData().getRole()));
            proverAttributes.put("url:AnnualSalary", new Attribute(obj.getData().getAnnualSalary()));
            storage.addAttributes(username, proverAttributes);
        }
    }

    private SignIdentityProof getProof(String proof) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.readValue(proof, SignIdentityProof.class);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}