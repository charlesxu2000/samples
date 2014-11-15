package com.example.security.saml;

import java.util.Map;

/**
 * Parameter required for generating and validating SAML assertion.
 */
public class SAMLParams
{
    /**
     * SAML assertion issuer.
     */
    private String  issuer;

    /**
     * SAML assertion subject id.
     */
    private String  nameID;

    /**
     * SAML assertion name schema.
     */
    private String  nameQualifier;

    /**
     * Default SAML assertion validation duration (in minutes).
     */
    private int     validationDuration;

    /**
     * Session id.
     */
    private String  sessionId;

    /**
     * Max session timeout (in minutes).
     */
    private int     maxSessionTimeoutInMinutes = 15;

    /**
     * SAML custom attributes.
     */
    private Map attributes;


    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getNameID() {
        return nameID;
    }

    public void setNameID(String nameID) {
        this.nameID = nameID;
    }

    public String getNameQualifier() {
        return nameQualifier;
    }

    public void setNameQualifier(String nameQualifier) {
        this.nameQualifier = nameQualifier;
    }

    public int getValidationDuration() {
        return validationDuration;
    }

    public void setValidationDuration(int validationDuration) {
        this.validationDuration = validationDuration;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public int getMaxSessionTimeoutInMinutes() {
        return maxSessionTimeoutInMinutes;
    }

    public void setMaxSessionTimeoutInMinutes(int maxSessionTimeoutInMinutes) {
        this.maxSessionTimeoutInMinutes = maxSessionTimeoutInMinutes;
    }

    public Map getAttributes() {
        return attributes;
    }

    public void setAttributes(Map attributes) {
        this.attributes = attributes;
    }

}
