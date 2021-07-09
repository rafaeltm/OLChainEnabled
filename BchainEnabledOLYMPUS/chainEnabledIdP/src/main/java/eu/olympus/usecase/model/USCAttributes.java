package eu.olympus.usecase.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.olympus.util.Util;


public class USCAttributes {
        @JsonProperty("url:Organization")
        private String organization;
        @JsonProperty("url:DateOfBirth")
        private String dateOfBirth; // RFC compliant
        @JsonProperty("url:Mail")
        private String mail;
        @JsonProperty("url:Role")
        private String role;
        @JsonProperty("url:AnnualSalary")
        private int annualSalary;

        public USCAttributes(){}

        public USCAttributes(String organization, String dateOfBirth, String mail, String role, int annualSalary) {
            this.organization = organization;
            this.dateOfBirth = Util.toRFC3339UTC(Util.fromRFC3339UTC(dateOfBirth));
            this.mail = mail;
            this.role = role;
            this.annualSalary = annualSalary;
        }

        public String getOrganization() {
            return organization;
        }

        public void setOrganization(String organization) {
            this.organization = organization;
        }

        public String getMail() {
            return mail;
        }

        public void setMail(String mail) {
            this.mail = mail;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }

        public String getDateOfBirth() {
            return dateOfBirth;
        }

        public void setDateOfBirth(String dateOfBirth) {
            this.dateOfBirth = Util.toRFC3339UTC(Util.fromRFC3339UTC(dateOfBirth));
        }

        public int getAnnualSalary() {
            return annualSalary;
        }

        public void setAnnualSalary(int annualSalary) {
            this.annualSalary = annualSalary;
        }

        @Override
        public String toString() {
            return "Attributes {" + '\n' + '\t' +
                    "organization = " + organization + "," + '\n' + '\t' +
                    "dateOfBirth = " + dateOfBirth + "," + '\n' + '\t' +
                    "mail = " + mail + "," + '\n' + '\t' +
                    "role = " + role + '\n' + '\t' +
                    "annualSalary = " + annualSalary + '\n' + '\t' +
                    '}';
        }
}
