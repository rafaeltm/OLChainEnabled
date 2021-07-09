import com.owlike.genson.Genson;
import com.owlike.genson.GensonBuilder;
import models.*;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

public final class DIDsAndStuffTest {
    final Genson genson = new GensonBuilder().rename("context", "@context").create();

    @Test
    public void idunno() {
        String s = "{\"aggpk\":null,\"did\":{\"@context\":\"https://www.w3.org/ns/did/v1\",\"context\":\"https://www.w3.org/ns/did/v1\",\"id\":\"did:umu:OL-vIdP:test1\",\"services\":[{\"endpoint\":\"10.1.6.6:9080\",\"id\":\"did:umu:OL-Partial-IdP:0:test1\",\"pk\":\"CnoKeAo6De5b4zbyer2OxnSH2lrVv7T9T+W+URmf2Kj+QMVVQZLM/CySsMZuhQ0lSGUh4bikZCL1QuU8R21sGxI6DGpOeFkE9Ueb5XNMISCdWaZU+aYVXzQ2qNo6ywvcXYioJdtAgBbPHzYAKAQsUNbohELdrRB6Lu4qcRJ6CngKOgDE6mk0hWQt1YkvuXTUCJ0Jl0/5cIVCUfEkzL4NuLymVBIqHfJG+DcVqrcdAxCzJ8RLRHSbhWW5hMYSOgjNRRYpir5shXNYenfwbMGTph+I1iD1cONPeRXTkDsFNpfqxNASZmp1lISh6UBGcZuJmT4aTJmezqEaegp4CjoO17+gWOl2cIDenZ7X3Ef3GzEl51Eowby3eWYvIgKkOuVCrjy9CGCVseZ6+dJe4oI6T2SG5+gabFB6EjoLzgnZRZ6kUKFTgaeezRQ+9IXYVd2c10kgrYTyAWC0TVcHLdY15OhBd+ITIaM7KQI9bVjgNsiplNtxIo4BChB1cmw6QW5udWFsU2FsYXJ5EnoKeAo6CX6gxPYA8sl2exaLD0XQnWnxFxsk3fpmf8M9AJigCfECoI5/EdtDl22ddMrL3XUDCGagGJ3+Mv0bNxI6DY/qmnDk/nvk0cZEO9YjJ5rPiwx2jjj3l/1uJvA+nATCSH+Hnx8prBbr1NnsIW6GO8TX68BhTJYm+iKGAQoIdXJsOlJvbGUSegp4CjoKjApIP3sptpwPjc5gCZm9LxyAP6+12t3U9w2uAR3WAMnikNtFPU79DIXw3zRWUsZn70ywijLAJuAREjoM0XO3Y5vT2dn41z2ltfIXhYi3VbnplIGuJsEAz2Kw7+8PM1ogHrm+6KnqrIQWsUcXhZ4G/v1gqa4HIo0BCg91cmw6RGF0ZU9mQmlydGgSegp4CjoF3p/5SgTacVx3HEGvk9an37++paomjfUL6gK3M1d4sEJcR/AfgaO7b0i8Ae66aIela7MJ770C8f8gEjoHIaP86YYT3isM9mMHbI+rJNQ6XXE2RSEx0isdN7+D43LhSxw4GSsTYwMfuI63ySfeWdDkmU9h4wIoIoYBCgh1cmw6TWFpbBJ6CngKOgppb/UeKxDt+1rJJqmRAQtXvWT3yD5XgD4YAZB360HTZc547XCMOziMO6plG9bMgn3dN5wqM/7wJKsSOgrEfb8rYkEIA/alJePMsxk/0FDWre+zrcQpW06yevqsTdEtDx6fMkq5W8aGzho2uhXojbn+Au1GU7QijgEKEHVybDpPcmdhbml6YXRpb24Segp4CjoUt9urfZLDK37Dkhhn/jIIE/KHVetskxlgZ+YoqiDO0zmXjFHBpxVWODuYovjQ4LCfoVgONNjosdGWEjoInD91OqZ+fTSi4u1lIBQRVCJI28s12kzKC9pMUToBO9gAA2Lxe6itUFZYSbPUCZw//oJEF7t8bcTD\"}]},\"docType\":\"VIdPRegistration\",\"idps\":[\"did:umu:OL-Partial-IdP:0:test1\"],\"schemas\":null,\"spawnDate\":\"2021-04-26T18:16:13\",\"status\":\"ACTIVE\"}";
        VIdPRegistration deserialize = genson.deserialize(s, VIdPRegistration.class);
        //deserialize.addSchema("essquecaweufnñw");
        Class<? extends ArrayList> aClass = deserialize.getDid().getServices().getClass();
        System.out.println(genson.serialize(genson.serialize(deserialize)));
        System.out.println(genson.serialize(genson.serialize(deserialize)));
//        DIDDocument serialize1 = genson.deserialize(diddocument, DIDDocument.class);
//        System.out.println(serialize1);
//        System.out.println(genson.deserialize(genson.serialize(serialize1), Service.class));

        String query = new JSONObject().put("selector", new JSONObject()
                .put("docType", Event.class.getSimpleName())).toString();
        long beforeLedger = System.nanoTime();
        System.out.println(query.toString());

        VIDPDocument raro = new VIDPDocument("raro", null, null);
        System.out.println("VIDP: "+genson.serialize(raro) );
        System.out.println("VIDP: "+genson.deserialize(genson.serialize(raro), VIDPDocument.class ));
        ;
    }

    @Test
    public void testUpdateIdppublickey(){
        ArrayList<IdPService> idps = new ArrayList<>();
        IdPService idPService = new IdPService("id", "endpoint", "pk");
        idps.add(idPService);
        VIDPDocument vidpDocument = new VIDPDocument("context", "id", idps);
        VIdPRegistration vIdPRegistration = new VIdPRegistration(vidpDocument, null, null, null);
        System.out.println(genson.serialize(vIdPRegistration));
        vIdPRegistration.getDid().updateIdP(idPService, "pknew");
        System.out.println(genson.serialize(vIdPRegistration));
    }


    public void ratatata(String parameter) {
        System.out.println(parameter);
        parameter = "changed";
        System.out.println(parameter);
    }
}
