package verifier.rest;

import java.util.List;

public class SetupModel {

    private List<String> urls;

    public SetupModel() {
    }

    public SetupModel(List<String> urls) {
        this.urls = urls;
    }

    public List<String> getUrls() {
        return urls;
    }

    public void setUrls(List<String> urls) {
        this.urls = urls;
    }
}
