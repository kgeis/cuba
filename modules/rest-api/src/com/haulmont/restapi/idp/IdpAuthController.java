/*
 * Copyright (c) 2008-2017 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.haulmont.restapi.idp;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.haulmont.bali.util.URLEncodeUtils;
import com.haulmont.cuba.core.global.Configuration;
import com.haulmont.cuba.security.app.LoginService;
import com.haulmont.cuba.security.global.IdpSession;
import com.haulmont.restapi.auth.OAuthTokenIssuer;
import com.haulmont.restapi.auth.OAuthTokenIssuer.OAuth2AccessTokenResult;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.*;

@RestController
public class IdpAuthController implements InitializingBean {

    private final Logger log = LoggerFactory.getLogger(IdpAuthController.class);

    @Inject
    protected Configuration configuration;
    @Inject
    protected OAuthTokenIssuer oAuthTokenIssuer;
    @Inject
    protected LoginService loginService;

    protected String idpBaseURL;
    protected String idpTrustedServicePassword;

    protected Set<HttpMethod> allowedRequestMethods = Collections.singleton(HttpMethod.POST);

    protected WebResponseExceptionTranslator providerExceptionHandler = new DefaultWebResponseExceptionTranslator();

    @RequestMapping(value = "/v2/idp/token", method = RequestMethod.GET)
    public ResponseEntity<OAuth2AccessToken> getAccessToken(Principal principal,
                                                            @RequestParam Map<String, String> parameters,
                                                            HttpServletRequest request)
            throws HttpRequestMethodNotSupportedException {

        if (!allowedRequestMethods.contains(HttpMethod.GET)) {
            throw new HttpRequestMethodNotSupportedException("GET");
        }

        return postAccessToken(principal, parameters, request);
    }

    @RequestMapping(value = "/v2/idp/token", method = RequestMethod.POST)
    public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal,
                                                             @RequestParam Map<String, String> parameters,
                                                             HttpServletRequest request)
            throws HttpRequestMethodNotSupportedException {

        if (!configuration.getConfig(RestIdpConfig.class).getIdpEnabled()) {
            log.debug("IDP authentication is disabled. Property cuba.rest.idp.enabled is false");

            throw new InvalidGrantException("IDP is not supported");
        }

        if (!(principal instanceof Authentication)) {
            throw new InsufficientAuthenticationException(
                    "There is no client authentication. Try adding an appropriate authentication filter.");
        }

        String grantType = parameters.get(OAuth2Utils.GRANT_TYPE);
        if (!"password".equals(grantType)) {
            throw new InvalidGrantException("grant type not supported for idp/token endpoint");
        }

        String username = parameters.get("username");
        String ipAddress = request.getRemoteAddr();

        checkBruteForceProtection(username, ipAddress);

        String idpTicket = parameters.get("ticket");

        OAuth2AccessTokenResult tokenResult =
                authenticate(username, idpTicket, request.getLocale(), ipAddress, parameters);

        return ResponseEntity.ok(tokenResult.getAccessToken());
    }

    @RequestMapping(value = "/v2/idp/login", method = RequestMethod.GET)
    public ResponseEntity login(@RequestParam("redirectUrl") String redirectUrl) {
        return ResponseEntity
                .status(HttpStatus.FOUND)
                .location(URI.create(getIdpRedirectUrl(redirectUrl)))
                .build();
    }

    protected String getIdpRedirectUrl(String redirectUrl) {
        String idpBaseURL = this.idpBaseURL;
        if (!idpBaseURL.endsWith("/")) {
            idpBaseURL += "/";
        }
        return idpBaseURL + "?sp=" +
                URLEncodeUtils.encodeUtf8(redirectUrl);
    }

    protected OAuth2AccessTokenResult authenticate(String username, String idpTicket, Locale locale,
                                                   String ipAddress, Map<String, String> parameters) {
        // todo
        IdpSession idpSession = getIdpSession(idpTicket);
        if (idpSession == null) {
            log.info("REST API authentication failed: {} {}", username, ipAddress);
            throw new BadCredentialsException("Bad credentials");
        }

        return oAuthTokenIssuer.issueToken(username, locale, Collections.emptyMap());
    }

    @Nullable
    protected IdpSession getIdpSession(String idpTicket) throws InvalidGrantException {
        String idpBaseURL = this.idpBaseURL;
        if (!idpBaseURL.endsWith("/")) {
            idpBaseURL += "/";
        }
        String idpTicketActivateUrl = idpBaseURL + "service/activate";

        HttpPost httpPost = new HttpPost(idpTicketActivateUrl);
        httpPost.setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.getMimeType());

        UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(Arrays.asList(
                new BasicNameValuePair("serviceProviderTicket", idpTicket),
                new BasicNameValuePair("trustedServicePassword", idpTrustedServicePassword)
        ), StandardCharsets.UTF_8);

        httpPost.setEntity(formEntity);

        HttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager();
        HttpClient client = HttpClientBuilder.create()
                .setConnectionManager(connectionManager)
                .build();

        String idpResponse;
        try {
            HttpResponse httpResponse = client.execute(httpPost);

            int statusCode = httpResponse.getStatusLine().getStatusCode();
            if (statusCode == 410) {
                // used old ticket
                return null;
            }

            if (statusCode != 200) {
                throw new RuntimeException("Idp respond with status " + statusCode);
            }

            idpResponse = new BasicResponseHandler().handleResponse(httpResponse);
        } catch (IOException e) {
            throw new RuntimeException("Unable to connect to IDP", e);
        } finally {
            connectionManager.shutdown();
        }

        IdpSession session;
        try {
            session = new Gson().fromJson(idpResponse, IdpSession.class);
        } catch (JsonSyntaxException e) {
            throw new RuntimeException("Unable to parse idp response", e);
        }

        return session;
    }

    protected void checkBruteForceProtection(String login, String ipAddress) {
        if (loginService.isBruteForceProtectionEnabled()) {
            if (loginService.loginAttemptsLeft(login, ipAddress) <= 0) {
                log.info("Blocked user login attempt: login={}, ip={}", login, ipAddress);
                throw new LockedException("User temporarily blocked");
            }
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        RestIdpConfig idpConfig = configuration.getConfig(RestIdpConfig.class);

        if (idpConfig.getIdpEnabled()) {
            checkRequiredConfigProperties(idpConfig);
        }
    }

    protected void checkRequiredConfigProperties(RestIdpConfig idpConfig) {
        List<String> missingProperties = new ArrayList<>();

        // todo implement
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
        log.error("Exception in LDAP auth controller", e);
        return new ResponseEntity<>(new OAuth2Exception("Server error", e), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<OAuth2Exception> handleBadCredentialsException(BadCredentialsException e) throws Exception {
        return getExceptionTranslator().translate(e);
    }

    @ExceptionHandler(ClientAuthenticationException.class)
    public ResponseEntity<OAuth2Exception> handleClientAuthenticationException(ClientAuthenticationException e)
            throws Exception {
        return getExceptionTranslator().translate(e);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<OAuth2Exception> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException e)
            throws Exception {
        log.info("Handling error: {}, {}", e.getClass().getSimpleName(), e.getMessage());
        return getExceptionTranslator().translate(e);
    }

    public WebResponseExceptionTranslator getExceptionTranslator() {
        return providerExceptionHandler;
    }

    public void setExceptionTranslator(WebResponseExceptionTranslator providerExceptionHandler) {
        this.providerExceptionHandler = providerExceptionHandler;
    }

    public Set<HttpMethod> getAllowedRequestMethods() {
        return allowedRequestMethods;
    }

    public void setAllowedRequestMethods(Set<HttpMethod> allowedRequestMethods) {
        this.allowedRequestMethods = allowedRequestMethods;
    }

    public String getIdpBaseURL() {
        return idpBaseURL;
    }

    public void setIdpBaseURL(String idpBaseURL) {
        this.idpBaseURL = idpBaseURL;
    }

    public String getIdpTrustedServicePassword() {
        return idpTrustedServicePassword;
    }

    public void setIdpTrustedServicePassword(String idpTrustedServicePassword) {
        this.idpTrustedServicePassword = idpTrustedServicePassword;
    }
}