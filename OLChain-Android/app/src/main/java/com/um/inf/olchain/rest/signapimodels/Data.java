package com.um.inf.olchain.rest.signapimodels;
import javax.annotation.Generated;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class Data {

    @SerializedName("url:Organization")
    @Expose
    private String urlOrganization;
    @SerializedName("url:DateOfBirth")
    @Expose
    private String urlDateOfBirth;
    @SerializedName("url:Mail")
    @Expose
    private String urlMail;
    @SerializedName("url:Role")
    @Expose
    private String urlRole;
    @SerializedName("url:AnnualSalary")
    @Expose
    private Integer urlAnnualSalary;

    public String getUrlOrganization() {
        return urlOrganization;
    }

    public void setUrlOrganization(String urlOrganization) {
        this.urlOrganization = urlOrganization;
    }

    public String getUrlDateOfBirth() {
        return urlDateOfBirth;
    }

    public void setUrlDateOfBirth(String urlDateOfBirth) {
        this.urlDateOfBirth = urlDateOfBirth;
    }

    public String getUrlMail() {
        return urlMail;
    }

    public void setUrlMail(String urlMail) {
        this.urlMail = urlMail;
    }

    public String getUrlRole() {
        return urlRole;
    }

    public void setUrlRole(String urlRole) {
        this.urlRole = urlRole;
    }

    public Integer getUrlAnnualSalary() {
        return urlAnnualSalary;
    }

    public void setUrlAnnualSalary(Integer urlAnnualSalary) {
        this.urlAnnualSalary = urlAnnualSalary;
    }

}