package com.github.wadahiro.keycloak.extension.mattermost;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.VerificationException;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.services.resources.admin.AdminMessageFormatter;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class CIBAAuthenticator implements Authenticator, AuthenticatorFactory {

    protected static final Logger LOGGER = Logger.getLogger(CIBAAuthenticator.class);

    protected static final String CONFIG_AUTHZ_ENDPOINT = "cibaAuthzEndpoint";
    protected static final String CONFIG_TOKEN_ENDPOINT = "cibaTokenEndpoint";
    protected static final String CONFIG_CLIENT_ID = "clientId";
    protected static final String CONFIG_CLIENT_SECRET = "clientSecret";
    protected static final String CONFIG_APPROVER_USERNAME = "approverUsername";

    @Override
    public boolean requiresUser() {
        return true;
    }

    protected String getConfig(AuthenticationFlowContext context, String key) {
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        return config.get(key);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String authzEndpoint = getConfig(context, CONFIG_AUTHZ_ENDPOINT);
        String clientId = getConfig(context, CONFIG_CLIENT_ID);
        String clientSecret = getConfig(context, CONFIG_CLIENT_SECRET);
        String approverUsername = getConfig(context, CONFIG_APPROVER_USERNAME);

        AdminMessageFormatter formatter = new AdminMessageFormatter(context.getSession(), context.getUser());
        String clientName = context.getAuthenticationSession().getClient().getName();
        clientName = clientName.replace("${", "").replace("}", "");
        String clientDisplayName = formatter.apply(clientName, new String[]{});

        String username = context.getUser().getUsername();

        try {
            SimpleHttp simpleHttp = SimpleHttp.doPost(authzEndpoint, context.getSession())
                    .param("client_id", clientId)
                    .param("client_secret", clientSecret)
                    .param("scope", "openid")
                    .param("login_hint", approverUsername)
                    .param("binding_message", username + "," + clientDisplayName);

            simpleHttp.header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

            SimpleHttp.Response res = simpleHttp.asResponse();
            JsonNode json = res.asJson();
            String authReqId = json.get("auth_req_id").asText();
            int expiresIn = json.get("expires_in").asInt();
            int interval = json.get("interval").asInt();

            context.getAuthenticationSession().setAuthNote("auth_req_id", authReqId);
            context.getAuthenticationSession().setAuthNote("expires_in", String.valueOf(expiresIn));
            context.getAuthenticationSession().setAuthNote("interval", String.valueOf(interval));

            context.challenge(challengeInfo(context.form(), "waitingAuthorization", String.valueOf(expiresIn)));
            return;

        } catch (IOException e) {
            LOGGER.error("Failed to request CIBA authz", e);
        }

        context.attempted();
        ;
        return;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String tokenEndpoint = getConfig(context, CONFIG_TOKEN_ENDPOINT);
        String clientId = getConfig(context, CONFIG_CLIENT_ID);
        String clientSecret = getConfig(context, CONFIG_CLIENT_SECRET);

        String authReqId = context.getAuthenticationSession().getAuthNote("auth_req_id");
        if (authReqId == null || authReqId.isEmpty()) {
            accessDenied(context, "accessDenied");
            return;
        }

        SimpleHttp simpleHttp = SimpleHttp.doPost(tokenEndpoint, context.getSession())
                .param("client_id", clientId)
                .param("client_secret", clientSecret)
                .param("grant_type", "urn:openid:params:grant-type:ciba")
                .param("auth_req_id", authReqId);

        try {
            SimpleHttp.Response response = simpleHttp.asResponse();

            if (response.getStatus() == 400) {
                // Not yet approved
                JsonNode errorRes = response.asJson();
                String error = errorRes.get("error").asText();
                if ("authorization_pending".equals(error)) {
                    LOGGER.info("authorization_pending");

                    context.challenge(challengeInfo(context.form(), "pendingAuthorization"));
                    return;
                } else if ("expired_token".equals(error)) {
                    LOGGER.info("expired_token");

                    context.getEvent().error(Errors.EXPIRED_CODE);
                    accessDenied(context, "expired");
                    return;
                } else if ("access_denied".equals(error)) {
                    LOGGER.info("access_denied");

                    context.getEvent().error(Errors.ACCESS_DENIED);
                    accessDenied(context, "accessDenied");
                    return;
                } else {
                    LOGGER.warnv("Not authorized yet: {0}", error);

                    // Continue...
                    context.challenge(challengeInfo(context.form(), "pendingAuthorization"));
                    return;
                }
            } else if (response.getStatus() != 200) {
                LOGGER.error("Unexpected CIBA token response");
                accessDenied(context, "Unexpected authentication response");
                return;
            }

            JsonNode idToken = response.asJson().get("id_token");
            if (idToken.isMissingNode()) {
                LOGGER.error("No id_token in the CIBA token");
                accessDenied(context, "Unexpected authentication response");
                return;
            }

            String encodedIDToken = idToken.asText();

            IDToken idt = context.getSession().tokens().decode(encodedIDToken, IDToken.class);
            try {
                TokenVerifier.createWithoutSignature(idt)
                        .withChecks(TokenManager.NotBeforeCheck.forModel(context.getRealm()), TokenVerifier.IS_ACTIVE)
                        .verify();
            } catch (VerificationException e) {
                LOGGER.error("Invalid id token", e);
                accessDenied(context, "accessDenied");
                return;
            }

            context.success();
            return;

        } catch (IOException e) {
            LOGGER.error("Failed to request CIBA token", e);
            accessDenied(context, "Unexpected authentication response");
            return;
        }
    }

    private void accessDenied(AuthenticationFlowContext context, String messageKey) {
        context.getEvent().error(Errors.ACCESS_DENIED);
        Response challenge = context.form()
                .setError(messageKey)
                .createErrorPage(Response.Status.UNAUTHORIZED);
        context.failure(AuthenticationFlowError.ACCESS_DENIED, challenge);
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new CIBAAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "x-ciba-authenticator";
    }

    Response challengeInfo(LoginFormsProvider form, String info, String... params) {
        return form
                .setInfo(info, params)
                .createForm("login-ciba.ftl");
    }

    @Override
    public String getDisplayType() {
        return "CIBA Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty p1 = new ProviderConfigProperty(CONFIG_AUTHZ_ENDPOINT, "CIBA Authz Endpoint",
                "Endpoint URL of CIBA authorization.",
                ProviderConfigProperty.STRING_TYPE, null);
        ProviderConfigProperty p2 = new ProviderConfigProperty(CONFIG_TOKEN_ENDPOINT, "CIBA Token Endpoint",
                "Endpoint URL of CIBA token.",
                ProviderConfigProperty.STRING_TYPE, null);
        ProviderConfigProperty p3 = new ProviderConfigProperty(CONFIG_CLIENT_ID, "CIBA Client ID",
                "Client ID of CIBA client.",
                ProviderConfigProperty.STRING_TYPE, null);
        ProviderConfigProperty p4 = new ProviderConfigProperty(CONFIG_CLIENT_SECRET, "CIBA Client Secret",
                "Client Secret of CIBA client.",
                ProviderConfigProperty.STRING_TYPE, null);
        ProviderConfigProperty p5 = new ProviderConfigProperty(CONFIG_APPROVER_USERNAME, "Approver usrename",
                "Approver username",
                ProviderConfigProperty.STRING_TYPE, null);

        return Arrays.asList(p1, p2, p3, p4, p5);
    }
}
