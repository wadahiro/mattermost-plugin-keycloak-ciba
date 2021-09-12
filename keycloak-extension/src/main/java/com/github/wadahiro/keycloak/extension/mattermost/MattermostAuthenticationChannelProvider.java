/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.wadahiro.keycloak.extension.mattermost;

import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.grants.ciba.channel.AuthenticationChannelProvider;
import org.keycloak.protocol.oidc.grants.ciba.channel.CIBAAuthenticationRequest;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.TokenUtil;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;
import java.io.IOException;

public class MattermostAuthenticationChannelProvider implements AuthenticationChannelProvider {

    protected KeycloakSession session;
    protected RealmModel realm;
    protected final String httpAuthenticationChannelUri;

    public MattermostAuthenticationChannelProvider(KeycloakSession session, String httpAuthenticationChannelUri) {
        this.session = session;
        this.realm = session.getContext().getRealm();
        this.httpAuthenticationChannelUri = httpAuthenticationChannelUri;
    }

    @Override
    public boolean requestAuthentication(CIBAAuthenticationRequest request, String infoUsedByAuthenticator) {
        // Creates JWT formatted/JWS signed/JWE encrypted Authentication Channel ID by the same manner in creating auth_req_id.
        // Authentication Channel ID binds Backchannel Authentication Request with Authentication by Authentication Device (AD).
        // JWE serialized Authentication Channel ID works as a bearer token. It includes client_id 
        // that can be used on Authentication Channel Callback Endpoint to recognize the Consumption Device (CD)
        // that sent Backchannel Authentication Request.

        // The following scopes should be displayed on AD:
        // 1. scopes specified explicitly as query parameter in the authorization request
        // 2. scopes specified implicitly as default client scope in keycloak

        checkAuthenticationChannel();

        ClientModel client = request.getClient();

        try {
            MattermostAuthenticationChannelRequest channelRequest = new MattermostAuthenticationChannelRequest();

            channelRequest.setScope(request.getScope());
            channelRequest.setBindingMessage(request.getBindingMessage());
            channelRequest.setLoginHint(infoUsedByAuthenticator);
            channelRequest.setConsentRequired(client.isConsentRequired());
            channelRequest.setAcrValues(request.getAcrValues());
            channelRequest.setAdditionalParameters(request.getOtherClaims());
            channelRequest.setAccessToken(createBearerToken(request, client));

            SimpleHttp simpleHttp = SimpleHttp.doPost(httpAuthenticationChannelUri, session)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .json(channelRequest);

            int status = simpleHttp.asStatus();

            if (status == Status.CREATED.getStatusCode()) {
                return true;
            }
        } catch (IOException ioe) {
            throw new RuntimeException("Authentication Channel Access failed.", ioe);
        }

        return false;
    }

    private String createBearerToken(CIBAAuthenticationRequest request, ClientModel client) {
        AccessToken bearerToken = new AccessToken();

        bearerToken.type(TokenUtil.TOKEN_TYPE_BEARER);
        bearerToken.issuer(request.getIssuer());
        bearerToken.id(request.getAuthResultId());
        bearerToken.issuedFor(client.getClientId());
        bearerToken.audience(request.getIssuer());
        bearerToken.exp(request.getExp());
        bearerToken.subject(request.getSubject());

        return session.tokens().encode(bearerToken);
    }

    protected void checkAuthenticationChannel() {
        if (httpAuthenticationChannelUri == null) {
            throw new RuntimeException("Mattermost Authentication Channel Request URI not set properly.");
        }
        if (!httpAuthenticationChannelUri.startsWith("http://") && !httpAuthenticationChannelUri.startsWith("https://")) {
            throw new RuntimeException("Mattermost Authentication Channel Request URI not set properly.");
        }
    }

    @Override
    public void close() {
    }
}
