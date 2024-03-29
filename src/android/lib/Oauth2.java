// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package com.cordova.plugin.oidc;

import android.net.Uri;
import android.os.Build;
import android.text.TextUtils;
import android.util.Base64;

import com.cordova.plugin.oidc.ChallengeResponseBuilder.ChallengeResponse;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.Locale;

/**
 * Base Oauth class.
 */
class Oauth2 {

    private AuthenticationRequest mRequest;

    private IWebRequestHandler mWebRequestHandler;

    private IJWSBuilder mJWSBuilder = new JWSBuilder();

    private static final String TAG = "Oauth";

    private boolean mRetryOnce = true;

    private static final int DELAY_TIME_PERIOD = 1000;

    private static final int MAX_RESILIENCY_ERROR_CODE = 599;
    
    private static final String DEFAULT_FRAGMENT = "/connect";

    private static final String DEFAULT_AUTHORIZE_ENDPOINT = "/authorize";

    private static final String DEFAULT_TOKEN_ENDPOINT = "/token";

    Oauth2(AuthenticationRequest request) {
        mRequest = request;
        mWebRequestHandler = null;
        mJWSBuilder = null;
    }

    public Oauth2(AuthenticationRequest request, IWebRequestHandler webRequestHandler) {
        mRequest = request;
        mWebRequestHandler = webRequestHandler;
        mJWSBuilder = null;
    }

    public Oauth2(AuthenticationRequest request, IWebRequestHandler webRequestHandler,
            IJWSBuilder jwsMessageBuilder) {
        mRequest = request;
        mWebRequestHandler = webRequestHandler;
        mJWSBuilder = jwsMessageBuilder;
    }

    public String getAuthorizationEndpoint() {
        final String endpoint = mRequest.getEndpointFragment();
        if (endpoint == null || endpoint.isEmpty()) {
            return mRequest.getAuthority() + DEFAULT_FRAGMENT + DEFAULT_AUTHORIZE_ENDPOINT;
        }
        else if (endpoint.toLowerCase(Locale.US).startsWith(AuthenticationConstants.Broker.REDIRECT_SSL_PREFIX)) {
            return endpoint + DEFAULT_AUTHORIZE_ENDPOINT;
        }
        else {
            return mRequest.getAuthority() + "/" + endpoint + DEFAULT_AUTHORIZE_ENDPOINT;
        }
    }

    public String getTokenEndpoint() {
        final String endpoint = mRequest.getEndpointFragment();
        if (endpoint == null || endpoint.isEmpty()) {
            return mRequest.getAuthority() + DEFAULT_FRAGMENT + DEFAULT_TOKEN_ENDPOINT;
        }
        else if (endpoint.toLowerCase(Locale.US).startsWith(AuthenticationConstants.Broker.REDIRECT_SSL_PREFIX)) {
            return endpoint + DEFAULT_TOKEN_ENDPOINT;
        }
        else {
            return mRequest.getAuthority() + "/" + endpoint + DEFAULT_TOKEN_ENDPOINT;
        }
    }

    private String getTokenResponseType() {

        final String responseType = mRequest.getResponseType();
        if (responseType == null || responseType.isEmpty()) {
            return AuthenticationConstants.OAuth2.ID_TOKEN;
        }
        else {
            return responseType;
        }
    }

    public String getAuthorizationEndpointQueryParameters() throws UnsupportedEncodingException {
        final Uri.Builder queryParameter = new Uri.Builder();

        final String tokenRespType = this.getTokenResponseType();
        queryParameter.appendQueryParameter(AuthenticationConstants.OAuth2.RESPONSE_TYPE, tokenRespType)
                .appendQueryParameter(AuthenticationConstants.OAuth2.CLIENT_ID,
                        URLEncoder.encode(mRequest.getClientId(),
                                AuthenticationConstants.ENCODING_UTF8))
                .appendQueryParameter(AuthenticationConstants.OAuth2.REDIRECT_URI,
                        URLEncoder.encode(mRequest.getRedirectUri(),
                                AuthenticationConstants.ENCODING_UTF8))
                .appendQueryParameter(AuthenticationConstants.OAuth2.STATE, encodeProtocolState())
			    .appendQueryParameter(AuthenticationConstants.OAuth2.NONCE, UUID.randomUUID().toString());

        if (tokenRespType.startsWith("code")) {
            queryParameter.appendQueryParameter(AuthenticationConstants.OAuth2.CODE_CHALLENGE, mRequest.GetCodeChallenge());
            queryParameter.appendQueryParameter(AuthenticationConstants.OAuth2.CODE_CHALLENGE_METHOD, "S256");
        }

        // reading extra qp supplied by developer
        final String extraQP = mRequest.getExtraQueryParamsAuthentication();
        // as another method, we can do it this way.
        // if (!StringExtensions.isNullOrBlank(extraQP)) {
        //     final String[] qSplit = extraQP.split("&");
        //     for (String qp : qSplit) {
        //         final String[] qpSplit = qp.split("=");                
        //         //queryParameter.appendQueryParameter(qpSplit[0],  URLEncoder.encode(URLDecoder.decode(qpSplit[1], AuthenticationConstants.ENCODING_UTF8), AuthenticationConstants.ENCODING_UTF8));
        //         queryParameter.appendQueryParameter(qpSplit[0],  URLDecoder.decode(qpSplit[1], AuthenticationConstants.ENCODING_UTF8));
        //         //queryParameter.appendQueryParameter(qpSplit[0],  qpSplit[1]);
        //     }            
        // }
        // append haschrome=1 if developer does not pass as extra qp
//        if (StringExtensions.isNullOrBlank(extraQP)
//                || !extraQP.contains(AuthenticationConstants.OAuth2.HAS_CHROME)) {
//            queryParameter.appendQueryParameter(AuthenticationConstants.OAuth2.HAS_CHROME, "1");
//        }

        // Claims challenge are opaque to the sdk, we're not going to do any merging if both extra qp and claims parameter
        // contain it. Also, if developer sends it in both places, server will fail it.
        if (!StringExtensions.isNullOrBlank(mRequest.getClaimsChallenge())) {
            queryParameter.appendQueryParameter(AuthenticationConstants.OAuth2.CLAIMS, mRequest.getClaimsChallenge());
        }

        String requestUrl = queryParameter.build().getQuery();
        if (!StringExtensions.isNullOrBlank(extraQP)) {
            String parsedQP = extraQP;
            if (!extraQP.startsWith("&")) {
                parsedQP = "&" + parsedQP;
            }
            requestUrl += parsedQP;
        }

        return requestUrl;
    }

    public String getCodeRequestUrl() throws UnsupportedEncodingException {
        return String.format("%s?%s", getAuthorizationEndpoint(),
                getAuthorizationEndpointQueryParameters());
    }

    public String buildTokenRequestMessage(String code, String codeVerifier) throws UnsupportedEncodingException {
        Logger.v(TAG, "Building request message for redeeming token with auth code.");
        
        return String.format("%s=%s&%s=%s&%s=%s&%s=%s&%s=%s",
                AuthenticationConstants.OAuth2.GRANT_TYPE,
                StringExtensions.urlFormEncode(AuthenticationConstants.OAuth2.AUTHORIZATION_CODE),

                AuthenticationConstants.OAuth2.CODE, StringExtensions.urlFormEncode(code),

                AuthenticationConstants.OAuth2.CLIENT_ID,
                StringExtensions.urlFormEncode(mRequest.getClientId()),

                AuthenticationConstants.OAuth2.CODE_VERIFIER,
                StringExtensions.urlFormEncode(codeVerifier),

                AuthenticationConstants.OAuth2.REDIRECT_URI,
                StringExtensions.urlFormEncode(mRequest.getRedirectUri()));
    }

    public String buildRefreshTokenRequestMessage(String refreshToken)
            throws UnsupportedEncodingException {
        Logger.v(TAG, "Building request message for redeeming token with refresh token.");
        
        String message = String.format("%s=%s&%s=%s&%s=%s",
                AuthenticationConstants.OAuth2.GRANT_TYPE,
                StringExtensions.urlFormEncode(AuthenticationConstants.OAuth2.REFRESH_TOKEN),

                AuthenticationConstants.OAuth2.REFRESH_TOKEN,
                StringExtensions.urlFormEncode(refreshToken),

                AuthenticationConstants.OAuth2.CLIENT_ID,
                StringExtensions.urlFormEncode(mRequest.getClientId()));

        if (!StringExtensions.isNullOrBlank(mRequest.getResource())) {
            message = String.format("%s&%s=%s", message, AuthenticationConstants.OIDC.RESOURCE,
                    StringExtensions.urlFormEncode(mRequest.getResource()));
        }

        return message;
    }

    public static AuthenticationResult processUIResponseParams(Map<String, String> response) throws AuthenticationException {

        final AuthenticationResult result;

        // Protocol error related
        if (response.containsKey(AuthenticationConstants.OAuth2.ERROR)) {
            // Error response from the server
            // CorrelationID will be same as in request headers. This is
            // retrieved in result in case it was not set.
            String correlationInResponse = response.get(AuthenticationConstants.OIDC.CORRELATION_ID);
            if (!StringExtensions.isNullOrBlank(correlationInResponse)) {
                try {
                    final UUID correlationId = UUID.fromString(correlationInResponse);
                    Logger.setCorrelationId(correlationId);
                } catch (IllegalArgumentException ex) {
                    Logger.e(TAG, "CorrelationId is malformed: " + correlationInResponse, "",
                            OIDCError.CORRELATION_ID_FORMAT);
                }
            }

            Logger.v(
                    TAG,
                    "OAuth2 error:" + response.get(AuthenticationConstants.OAuth2.ERROR)
                            + " Description:"
                            + response.get(AuthenticationConstants.OAuth2.ERROR_DESCRIPTION));

            result = new AuthenticationResult(response.get(AuthenticationConstants.OAuth2.ERROR),
                    response.get(AuthenticationConstants.OAuth2.ERROR_DESCRIPTION),
                    response.get(AuthenticationConstants.OAuth2.ERROR_CODES));

        } else if (response.containsKey(AuthenticationConstants.OAuth2.CODE)) {
            result = new AuthenticationResult(response.get(AuthenticationConstants.OAuth2.CODE));
		} else if (response.containsKey(AuthenticationConstants.OAuth2.ACCESS_TOKEN)) {
			// Token response
			boolean isMultiResourceToken = false;
			String expiresIn = response.get(AuthenticationConstants.OAuth2.EXPIRES_IN);
			Calendar expires = new GregorianCalendar();

			// Compute token expiration
			expires.add(
				Calendar.SECOND,
				expiresIn == null || expiresIn.isEmpty() ? AuthenticationConstants.DEFAULT_EXPIRATION_TIME_SEC
					: Integer.parseInt(expiresIn));

			final String refreshToken = response.get(AuthenticationConstants.OAuth2.REFRESH_TOKEN);
			if (response.containsKey(AuthenticationConstants.OIDC.RESOURCE)
				&& !StringExtensions.isNullOrBlank(refreshToken)) {
				isMultiResourceToken = true;
			}

			UserInfo userinfo = null;
			String tenantId = null;
			String rawIdToken = null;
			if (response.containsKey(AuthenticationConstants.OAuth2.ID_TOKEN)) {
				// IDtoken is related to Azure AD and returned with token
				// response. ADFS does not return that.
				rawIdToken = response.get(AuthenticationConstants.OAuth2.ID_TOKEN);
				if (!StringExtensions.isNullOrBlank(rawIdToken)) {
					Logger.v(TAG, "Id token was returned, parsing id token.");
					IdToken tokenParsed = new IdToken(rawIdToken);
					tenantId = tokenParsed.getTenantId();
					userinfo = new UserInfo(tokenParsed);
				} else {
					Logger.v(TAG, "IdToken was not returned from token request.");
				}
			}

			String familyClientId = null;

			result = new AuthenticationResult(
				response.get(AuthenticationConstants.OAuth2.ACCESS_TOKEN), refreshToken, expires.getTime(),
				isMultiResourceToken, userinfo, tenantId, rawIdToken, null);

			if (response.containsKey(AuthenticationConstants.OAuth2.EXT_EXPIRES_IN)) {
				final String extendedExpiresIn = response.get(AuthenticationConstants.OAuth2.EXT_EXPIRES_IN);
				final Calendar extendedExpires = new GregorianCalendar();
				// Compute extended token expiration
				extendedExpires.add(
					Calendar.SECOND,
					StringExtensions.isNullOrBlank(extendedExpiresIn) ? AuthenticationConstants.DEFAULT_EXPIRATION_TIME_SEC
						: Integer.parseInt(extendedExpiresIn));
				result.setExtendedExpiresOn(extendedExpires.getTime());
			}

			//Set family client id on authentication result for TokenCacheItem to pick up
			result.setFamilyClientId(familyClientId);
		} else if (response.containsKey(AuthenticationConstants.OAuth2.ID_TOKEN)) {
			// Token response

			Calendar expires = new GregorianCalendar();

			// Compute token expiration



			UserInfo userinfo = null;
			String tenantId = null;
			String rawIdToken = null;
			// IDtoken is related to Azure AD and returned with token
			// response. ADFS does not return that.
			rawIdToken = response.get(AuthenticationConstants.OAuth2.ID_TOKEN);
			if (!StringExtensions.isNullOrBlank(rawIdToken)) {
				Logger.v(TAG, "Id token was returned, parsing id token.");
				IdToken tokenParsed = new IdToken(rawIdToken);
				tenantId = tokenParsed.getTenantId();
				userinfo = new UserInfo(tokenParsed);

				int expiresIn = tokenParsed.getExpiration();

				expires.add(
					Calendar.SECOND,
					expiresIn > 0 ? expiresIn : AuthenticationConstants.DEFAULT_EXPIRATION_TIME_SEC);

			} else {
				Logger.v(TAG, "IdToken was not returned from token request.");
			}

			String familyClientId = null;

			result = new AuthenticationResult(
				response.get(AuthenticationConstants.OAuth2.ID_TOKEN), null, expires.getTime(),
				false, userinfo, tenantId, rawIdToken, null);

			if (response.containsKey(AuthenticationConstants.OAuth2.EXT_EXPIRES_IN)) {
				final String extendedExpiresIn = response.get(AuthenticationConstants.OAuth2.EXT_EXPIRES_IN);
				final Calendar extendedExpires = new GregorianCalendar();
				// Compute extended token expiration
				extendedExpires.add(
					Calendar.SECOND,
					StringExtensions.isNullOrBlank(extendedExpiresIn) ? AuthenticationConstants.DEFAULT_EXPIRATION_TIME_SEC
						: Integer.parseInt(extendedExpiresIn));
				result.setExtendedExpiresOn(extendedExpires.getTime());
			}

			//Set family client id on authentication result for TokenCacheItem to pick up
			result.setFamilyClientId(familyClientId);
		}
        else {
            result = null;
        }

        return result;
    }

    private static void extractJsonObjects(Map<String, String> responseItems, String jsonStr)
            throws JSONException {
        final JSONObject jsonObject = new JSONObject(jsonStr);

        final Iterator<?> i = jsonObject.keys();

        while (i.hasNext()) {
            final String key = (String) i.next();
            responseItems.put(key, jsonObject.getString(key));
        }
    }

    public AuthenticationResult refreshToken(String refreshToken) throws IOException,
            AuthenticationException {
        final String requestMessage;
        if (mWebRequestHandler == null) {
            Logger.v(TAG, "Web request is not set correctly");
            throw new IllegalArgumentException("webRequestHandler is null.");
        }

        // Token request message
        try {
            requestMessage = buildRefreshTokenRequestMessage(refreshToken);
        } catch (UnsupportedEncodingException encoding) {
            Logger.e(TAG, encoding.getMessage(), "", OIDCError.ENCODING_IS_NOT_SUPPORTED, encoding);
            return null;
        }

        final Map<String, String> headers = getRequestHeaders();

        // Refresh token endpoint needs to send header field for device
        // challenge
        headers.put(AuthenticationConstants.Broker.CHALLENGE_TLS_INCAPABLE,
                AuthenticationConstants.Broker.CHALLENGE_TLS_INCAPABLE_VERSION);
        Logger.v(TAG, "Sending request to redeem token with refresh token.");
        return postMessage(requestMessage, headers);
    }

    /**
     * parse final url for code(normal flow) or token(implicit flow) and then it
     * proceeds to next step.
     * 
     * @param authorizationUrl browser reached to this final url and it has code
     *            or token for next step
     * @return Token in the AuthenticationResult. Null result if response does
     *         not have protocol error.
     * @throws IOException
     * @throws AuthenticationException
     */
    public AuthenticationResult getToken(String authorizationUrl)
            throws IOException, AuthenticationException {

        if (StringExtensions.isNullOrBlank(authorizationUrl)) {
            throw new IllegalArgumentException("authorizationUrl");
        }

        // Success
        HashMap<String, String> parameters = StringExtensions.getUrlParameters(authorizationUrl);
        String encodedState = parameters.get("state");
        String state = decodeProtocolState(encodedState);

        if (!StringExtensions.isNullOrBlank(state)) {

            // We have encoded state at the end of the url
            Uri stateUri = Uri.parse("http://state/path?" + state);
            String authorizationUri = stateUri.getQueryParameter("a");
            String resource = stateUri.getQueryParameter("r");

            if (!StringExtensions.isNullOrBlank(authorizationUri)
                    && !StringExtensions.isNullOrBlank(resource)
                    && resource.equalsIgnoreCase(mRequest.getResource())) {

                AuthenticationResult result = processUIResponseParams(parameters);

                
                // Check if we have code
                if (result != null && result.getCode() != null && !result.getCode().isEmpty()) {

                    //Get token and use external callback to set result
                    return getTokenForCode(result.getCode());
                }
                //SPIKE: end of commenting out!
				//result.codeIsAccessToken(); // SPIKE: our new function to set the access token to the code!
                
                return result;
            } else {
                throw new AuthenticationException(OIDCError.AUTH_FAILED_BAD_STATE);
            }
        } else {
            // The response from the server had no state
            throw new AuthenticationException(OIDCError.AUTH_FAILED_NO_STATE);
        }
    }

    /**
     * get code and exchange for token.
     * 
     * @param code the authorization code for which Authentication result is needed
     * @return AuthenticationResult
     * @throws IOException
     * @throws AuthenticationException
     */
    public AuthenticationResult getTokenForCode(String code) throws IOException, AuthenticationException {

        final String requestMessage;
        if (mWebRequestHandler == null) {
            throw new IllegalArgumentException("webRequestHandler");
        }

        // Token request message
        try {
            requestMessage = buildTokenRequestMessage(code, mRequest.GetCodeVerifier());
        } catch (UnsupportedEncodingException encoding) {
            Logger.e(TAG, encoding.getMessage(), "", OIDCError.ENCODING_IS_NOT_SUPPORTED, encoding);
            return null;
        }

        final Map<String, String> headers = getRequestHeaders();

        Logger.v(TAG, "Sending request to redeem token with auth code.");
        return postMessage(requestMessage, headers);
    }

    private AuthenticationResult postMessage(String requestMessage, Map<String, String> headers)
            throws IOException, AuthenticationException {
        AuthenticationResult result = null;
        final HttpEvent httpEvent = startHttpEvent();

        final URL authority = StringExtensions.getUrl(getTokenEndpoint());
        if (authority == null) {
            stopHttpEvent(httpEvent);
            throw new AuthenticationException(OIDCError.DEVELOPER_AUTHORITY_IS_NOT_VALID_URL);
        }

        httpEvent.setHttpPath(authority);

        try {
            mWebRequestHandler.setRequestCorrelationId(mRequest.getCorrelationId());
            ClientMetrics.INSTANCE.beginClientMetricsRecord(authority, mRequest.getCorrelationId(),
                    headers);
            HttpWebResponse response = mWebRequestHandler.sendPost(authority, headers,
                    requestMessage.getBytes(AuthenticationConstants.ENCODING_UTF8),
                    "application/x-www-form-urlencoded");
            httpEvent.setResponseCode(response.getStatusCode());
            httpEvent.setCorrelationId(mRequest.getCorrelationId().toString());
            stopHttpEvent(httpEvent);

            if (response.getStatusCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
                if (response.getResponseHeaders() != null
                        && response.getResponseHeaders().containsKey(
                                AuthenticationConstants.Broker.CHALLENGE_REQUEST_HEADER)) {

                    // Device certificate challenge will send challenge request
                    // in 401 header.
                    String challengeHeader = response.getResponseHeaders()
                            .get(AuthenticationConstants.Broker.CHALLENGE_REQUEST_HEADER).get(0);
                    Logger.v(TAG, "Device certificate challenge request:" + challengeHeader);
                    if (!StringExtensions.isNullOrBlank(challengeHeader)) {

                        // Handle each specific challenge header
                        if (StringExtensions.hasPrefixInHeader(challengeHeader,
                                AuthenticationConstants.Broker.CHALLENGE_RESPONSE_TYPE)) {
                            final HttpEvent challengeHttpEvent = startHttpEvent();
                            challengeHttpEvent.setHttpPath(authority);
                            Logger.v(TAG, "Received pkeyAuth device challenge.");
                            ChallengeResponseBuilder certHandler = new ChallengeResponseBuilder(
                                    mJWSBuilder);
                            Logger.v(TAG, "Processing device challenge");
                            final ChallengeResponse challengeResponse = certHandler
                                    .getChallengeResponseFromHeader(challengeHeader,
                                            authority.toString());
                            headers.put(AuthenticationConstants.Broker.CHALLENGE_RESPONSE_HEADER,
                                    challengeResponse.getAuthorizationHeaderValue());
                            Logger.v(TAG, "Sending request with challenge response");
                            response = mWebRequestHandler.sendPost(authority, headers,
                                    requestMessage.getBytes(AuthenticationConstants.ENCODING_UTF8),
                                    "application/x-www-form-urlencoded");
                            challengeHttpEvent.setResponseCode(response.getStatusCode());
                            challengeHttpEvent.setCorrelationId(mRequest.getCorrelationId().toString());
                            stopHttpEvent(challengeHttpEvent);
                        }
                    } else {
                        throw new AuthenticationException(
							OIDCError.DEVICE_CERTIFICATE_REQUEST_INVALID,
                                "Challenge header is empty");
                    }
                } else {
                    // AAD server returns 401 response for wrong request
                    // messages
                    Logger.v(TAG, "401 http status code is returned without authorization header");
                }
            }

            boolean isBodyEmpty = TextUtils.isEmpty(response.getBody());
            if (!isBodyEmpty) {
                // Protocol related errors will read the error stream and report
                // the error and error description
                Logger.v(TAG, "Token request does not have exception");
                try {
                    result = processTokenResponse(response, httpEvent);
                } catch (final ServerRespondingWithRetryableException e) {
                    result = retry(requestMessage, headers);
                    if (result != null) {
                        return result;
                    }

                    if (mRequest.getIsExtendedLifetimeEnabled()) {
                        Logger.v(TAG, "WebResponse is not a success due to: " + response.getStatusCode());
                        throw e;
                    } else {
                        Logger.v(TAG, "WebResponse is not a success due to: " + response.getStatusCode());
                        throw new AuthenticationException(OIDCError.SERVER_ERROR, "WebResponse is not a success due to: " + response.getStatusCode());
                    }
                }
                ClientMetrics.INSTANCE.setLastError(null);
            }
            if (result == null) {
                // non-protocol related error
                String errMessage = isBodyEmpty ? "Status code:" + response.getStatusCode() : response.getBody();
                Logger.e(TAG, "Server error message", errMessage, OIDCError.SERVER_ERROR);
                throw new AuthenticationException(OIDCError.SERVER_ERROR, errMessage);
            } else {
                ClientMetrics.INSTANCE.setLastErrorCodes(result.getErrorCodes());
            }
        } catch (final UnsupportedEncodingException e) {
            ClientMetrics.INSTANCE.setLastError(null);
            Logger.e(TAG, e.getMessage(), "", OIDCError.ENCODING_IS_NOT_SUPPORTED, e);
            throw e;
        } catch (final SocketTimeoutException e) {
            result = retry(requestMessage, headers);
            if (result != null) {
                return result;
            }

            ClientMetrics.INSTANCE.setLastError(null);
            if (mRequest.getIsExtendedLifetimeEnabled()) {
                Logger.e(TAG, e.getMessage(), "", OIDCError.SERVER_ERROR, e);
                throw new ServerRespondingWithRetryableException(e.getMessage(), e);
            } else {
                Logger.e(TAG, e.getMessage(), "", OIDCError.SERVER_ERROR, e);
                throw e;
            }
        } catch (final IOException e) {
            ClientMetrics.INSTANCE.setLastError(null);
            Logger.e(TAG, e.getMessage(), "", OIDCError.SERVER_ERROR, e);
            throw e;
        } finally {
            ClientMetrics.INSTANCE.endClientMetricsRecord(ClientMetricsEndpointType.TOKEN,
                    mRequest.getCorrelationId());
        }
        return result;
    }
    
    private AuthenticationResult retry(String requestMessage, Map<String, String> headers) throws IOException, AuthenticationException {
        //retry once if there is an observation of a network timeout by the client 
        if (mRetryOnce) {
            mRetryOnce = false;
            try {
                Thread.sleep(DELAY_TIME_PERIOD);
            } catch (final InterruptedException exception) {
                Logger.v(TAG, "The thread is interrupted while it is sleeping. " + exception);
            }

            Logger.v(TAG, "Try again...");
            return postMessage(requestMessage, headers);
        }

        return null;
    }

    public static String decodeProtocolState(String encodedState) throws UnsupportedEncodingException {

        if (!StringExtensions.isNullOrBlank(encodedState)) {
            byte[] stateBytes = Base64.decode(encodedState, Base64.NO_PADDING | Base64.URL_SAFE);

            return new String(stateBytes, "UTF-8");
        }

        return null;
    }

    public String encodeProtocolState() throws UnsupportedEncodingException {
        String state = String.format("a=%s&r=%s", mRequest.getAuthority(), mRequest.getResource());
        return Base64.encodeToString(state.getBytes("UTF-8"), Base64.NO_PADDING | Base64.URL_SAFE);
    }

    private Map<String, String> getRequestHeaders() {
        final Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        return headers;
    }

    /**
     * Extract AuthenticationResult object from response body if available.
     * 
     * @param webResponse the web response from which authentication result will be constructed
     * @return AuthenticationResult
     */
    private AuthenticationResult processTokenResponse(HttpWebResponse webResponse, final HttpEvent httpEvent)
            throws AuthenticationException {
        AuthenticationResult result;
        String correlationIdInHeader = null;
        if (webResponse.getResponseHeaders() != null) {
            if (webResponse.getResponseHeaders().containsKey(
                    AuthenticationConstants.OIDC.CLIENT_REQUEST_ID)) {
                // headers are returning as a list
                List<String> listOfHeaders = webResponse.getResponseHeaders().get(
                        AuthenticationConstants.OIDC.CLIENT_REQUEST_ID);
                if (listOfHeaders != null && listOfHeaders.size() > 0) {
                    correlationIdInHeader = listOfHeaders.get(0);
                }
            }

            if (webResponse.getResponseHeaders().containsKey(AuthenticationConstants.OIDC.REQUEST_ID_HEADER)) {
                // headers are returning as a list
                List<String> listOfHeaders = webResponse.getResponseHeaders().get(
                        AuthenticationConstants.OIDC.REQUEST_ID_HEADER);
                if (listOfHeaders != null && listOfHeaders.size() > 0) {
                    Logger.v(TAG, "x-ms-request-id: " + listOfHeaders.get(0));
                    httpEvent.setRequestIdHeader(listOfHeaders.get(0));
                }
            }
        }

        final int statusCode = webResponse.getStatusCode();

        if (statusCode == HttpURLConnection.HTTP_OK
                || statusCode == HttpURLConnection.HTTP_BAD_REQUEST
                || statusCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
            try {
                result = parseJsonResponse(webResponse.getBody());
                if (result != null) {
                    httpEvent.setOauthErrorCode(result.getErrorCode());
                }
            } catch (final JSONException jsonException) {
                throw new AuthenticationException(OIDCError.SERVER_INVALID_JSON_RESPONSE, "Can't parse server response " + webResponse.getBody(), jsonException);
            }
        } else if (statusCode >= HttpURLConnection.HTTP_INTERNAL_ERROR && statusCode <= MAX_RESILIENCY_ERROR_CODE) {
            throw new ServerRespondingWithRetryableException("Server Error " + statusCode + " " + webResponse.getBody());
        } else {
            throw new AuthenticationException(OIDCError.SERVER_ERROR, "Unexpected server response " + statusCode + " " + webResponse.getBody());
        }

        // Set correlationId in the result
        if (correlationIdInHeader != null && !correlationIdInHeader.isEmpty()) {
            try {
                UUID correlation = UUID.fromString(correlationIdInHeader);
                if (!correlation.equals(mRequest.getCorrelationId())) {
                    Logger.w(TAG, "CorrelationId is not matching", "",
						OIDCError.CORRELATION_ID_NOT_MATCHING_REQUEST_RESPONSE);
                }

                Logger.v(TAG, "Response correlationId:" + correlationIdInHeader);
            } catch (IllegalArgumentException ex) {
                Logger.e(TAG, "Wrong format of the correlation ID:" + correlationIdInHeader, "",
					OIDCError.CORRELATION_ID_FORMAT, ex);
            }
        }

        return result;
    }

    private AuthenticationResult parseJsonResponse(final String responseBody)
            throws JSONException,
            AuthenticationException {
        final Map<String, String> responseItems = new HashMap<>();
        extractJsonObjects(responseItems, responseBody);
        return processUIResponseParams(responseItems);
    }

    private HttpEvent startHttpEvent() {
        final HttpEvent httpEvent = new HttpEvent(EventStrings.HTTP_EVENT);
        httpEvent.setRequestId(mRequest.getTelemetryRequestId());
        httpEvent.setMethod(EventStrings.HTTP_METHOD_POST);
        Telemetry.getInstance().startEvent(mRequest.getTelemetryRequestId(), EventStrings.HTTP_EVENT);
        return httpEvent;
    }

    private void stopHttpEvent(final HttpEvent httpEvent) {
        Telemetry.getInstance().stopEvent(mRequest.getTelemetryRequestId(), httpEvent,
                EventStrings.HTTP_EVENT);
    }
}
