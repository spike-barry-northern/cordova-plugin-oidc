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

import android.util.Base64;

import androidx.annotation.Nullable;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * Represent request and keeps authorization code and similar info.
 */
class AuthenticationRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final int DELIM_NOT_FOUND = -1;

    private static final String UPN_DOMAIN_SUFFIX_DELIM = "@";

    private int mRequestId = 0;

    private String mAuthority = null;

    private String mEndpointFragment = null;

    private String mResponseType = null;

    private String mRedirectUri = null;

    private String mResource = null;

    private String mClientId = null;

    private String mLoginHint = null;

    private String mUserId = null;

    private String mBrokerAccountName = null;

    private UUID mCorrelationId;

    private String mExtraQueryParamsAuthentication;

    private PromptBehavior mPrompt;

    private boolean mSilent = false;

    private String mVersion = null;

    private UserIdentifierType mIdentifierType;

    private boolean mIsExtendedLifetimeEnabled = false;

    private String mTelemetryRequestId;

    private String mClaimsChallenge;

    private String codeVarifier = null;

    private static final String TAG = "AuthenticationRequest";

    /**
     * Developer can use acquireToken(with loginhint) or acquireTokenSilent(with
     * userid), so this sets the type of the request.
     */
    enum UserIdentifierType {
        UniqueId, LoginHint, NoUser
    }

    public AuthenticationRequest() {
        mIdentifierType = UserIdentifierType.NoUser;
    }

    public AuthenticationRequest(String authority, String resource, String client, String redirect,
                                 String loginhint, PromptBehavior prompt, String extraQueryParams, UUID correlationId,
                                 boolean isExtendedLifetimeEnabled, final String claimsChallenge, 
                                 String endpointFragment, String responseType) {
        mAuthority = authority;
        mEndpointFragment = endpointFragment;
        mResponseType = responseType;
        mResource = resource;
        mClientId = client;
        mRedirectUri = redirect;
        mLoginHint = loginhint;
        mBrokerAccountName = mLoginHint;
        mPrompt = prompt;
        mExtraQueryParamsAuthentication = extraQueryParams;
        mCorrelationId = correlationId;
        mIdentifierType = UserIdentifierType.NoUser;
        mIsExtendedLifetimeEnabled = isExtendedLifetimeEnabled;
        mClaimsChallenge = claimsChallenge;
    }

    public AuthenticationRequest(String authority, String resource, String client, String redirect,
                                 String loginhint, UUID requestCorrelationId, boolean isExtendedLifetimeEnabled, 
                                 String endpointFragment, String responseType) {
        mAuthority = authority;
        mEndpointFragment = endpointFragment;
        mResponseType = responseType;
        mResource = resource;
        mClientId = client;
        mRedirectUri = redirect;
        mLoginHint = loginhint;
        mBrokerAccountName = mLoginHint;
        mCorrelationId = requestCorrelationId;
        mIsExtendedLifetimeEnabled = isExtendedLifetimeEnabled;
    }

    public AuthenticationRequest(String authority, String resource, String client, String redirect,
                                 String loginhint, boolean isExtendedLifetimeEnabled, 
                                 String endpointFragment, String responseType) {
        mAuthority = authority;
        mEndpointFragment = endpointFragment;
        mResponseType = responseType;
        mResource = resource;
        mClientId = client;
        mRedirectUri = redirect;
        mLoginHint = loginhint;
        mBrokerAccountName = mLoginHint;
        mIsExtendedLifetimeEnabled = isExtendedLifetimeEnabled;
    }

    public AuthenticationRequest(String authority, String resource, String clientid, boolean isExtendedLifetimeEnabled, 
                                 String endpointFragment, String responseType) {
        mAuthority = authority;
        mEndpointFragment = endpointFragment;
        mResponseType = responseType;
        mResource = resource;
        mClientId = clientid;
        mIsExtendedLifetimeEnabled = isExtendedLifetimeEnabled;
    }

    /**
     * Cache usage and refresh token requests.
     *
     * @param authority     Authority URL
     * @param resource      Resource that is requested
     * @param clientid      ClientId for the app
     * @param userid        user id
     * @param correlationId for logging
     */
    public AuthenticationRequest(String authority, String resource, String clientid, String userid,
                                 UUID correlationId, boolean isExtendedLifetimeEnabled, 
                                 String endpointFragment, String responseType) {
        mAuthority = authority;
        mEndpointFragment = endpointFragment;
        mResponseType = responseType;
        mResource = resource;
        mClientId = clientid;
        mUserId = userid;
        mCorrelationId = correlationId;
        mIsExtendedLifetimeEnabled = isExtendedLifetimeEnabled;
    }

    public AuthenticationRequest(String authority, String resource, String clientId,
                                 UUID correlationId, boolean isExtendedLifetimeEnabled, 
                                 String endpointFragment, String responseType) {
        mAuthority = authority;
        mEndpointFragment = endpointFragment;
        mResponseType = responseType;
        mClientId = clientId;
        mResource = resource;
        mCorrelationId = correlationId;
        mIsExtendedLifetimeEnabled = isExtendedLifetimeEnabled;
    }

    public String getAuthority() {
        return mAuthority;
    }

    public void setAuthority(String authority) {
        mAuthority = authority;
    }

    public String getEndpointFragment() {
        return mEndpointFragment;
    }

    public String getResponseType() {
        return mResponseType;
    }

    public String getRedirectUri() {
        return mRedirectUri;
    }

    public String getResource() {
        return mResource;
    }

    public String getClientId() {
        return mClientId;
    }

    public String getLoginHint() {
        return mLoginHint;
    }

    public UUID getCorrelationId() {
        return this.mCorrelationId;
    }

    public String getExtraQueryParamsAuthentication() {
        return mExtraQueryParamsAuthentication;
    }

    public String getLogInfo() {
        return String.format("Request authority:%s resource:%s clientid:%s", mAuthority, mResource,
                mClientId);
    }

    public PromptBehavior getPrompt() {
        return mPrompt;
    }

    public void setPrompt(PromptBehavior prompt) {
        this.mPrompt = prompt;
    }

    /**
     * @return the mRequestId related to the delegate
     */
    public int getRequestId() {
        return mRequestId;
    }

    /**
     * @param requestId the requestId to set
     */
    public void setRequestId(int requestId) {
        this.mRequestId = requestId;
    }

    public String getBrokerAccountName() {
        return mBrokerAccountName;
    }

    public void setBrokerAccountName(String brokerAccountName) {
        this.mBrokerAccountName = brokerAccountName;
    }

    void setLoginHint(String name) {
        mLoginHint = name;
    }

    public String getUserId() {
        return mUserId;
    }

    public void setUserId(String userId) {
        this.mUserId = userId;
    }

    public boolean isSilent() {
        return mSilent;
    }

    public void setSilent(boolean silent) {
        this.mSilent = silent;
    }

    public String getVersion() {
        return mVersion;
    }

    public void setVersion(String version) {
        this.mVersion = version;
    }

    public UserIdentifierType getUserIdentifierType() {
        return mIdentifierType;
    }

    public void setUserIdentifierType(UserIdentifierType user) {
        mIdentifierType = user;
    }

    public boolean getIsExtendedLifetimeEnabled() {
        return mIsExtendedLifetimeEnabled;
    }

    public void setClaimsChallenge(final String claimsChallenge) {
        mClaimsChallenge = claimsChallenge;
    }

    public String getClaimsChallenge() {
        return mClaimsChallenge;
    }

    /**
     * Get either loginhint or user id based what's passed in the request.
     */
    String getUserFromRequest() {
        if (UserIdentifierType.LoginHint == mIdentifierType) {
            return mLoginHint;
        } else if (UserIdentifierType.UniqueId == mIdentifierType) {
            return mUserId;
        }

        return null;
    }

    /**
     * Gets the domain suffix of User Principal Name.
     *
     * @return the domain suffix or null if unavailable
     */
    @Nullable
    String getUpnSuffix() {
        final String hint = getLoginHint();
        String suffix = null;
        if (hint != null) {
            final int dIndex = hint.lastIndexOf(UPN_DOMAIN_SUFFIX_DELIM);
            suffix = DELIM_NOT_FOUND == dIndex ? null : hint.substring(dIndex + 1);
        }
        return suffix;
    }

    void setTelemetryRequestId(final String telemetryRequestId) {
        mTelemetryRequestId = telemetryRequestId;
    }

    String getTelemetryRequestId() {
        return mTelemetryRequestId;
    }

    public String GetCodeVarifier() {
        if (this.codeVarifier == null) {
            SecureRandom sr = new SecureRandom();
            byte[] code = new byte[32];
            sr.nextBytes(code);
            String verifier = Base64.encodeToString(code, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);

            this.codeVarifier = verifier; //"3a95b913-e8f7-4189-97c6-e58ce0785d4d";
        }
        return this.codeVarifier;
    }

    public String GetCodeChallenge() {

        try {
            byte[] bytes = this.GetCodeVarifier().getBytes("US-ASCII");

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes, 0, bytes.length);
            byte[] digest = md.digest();
            String challenge = Base64.encodeToString(digest, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
            return challenge; //"8108ab1612e3041d66af6da85db54c3226679126d89b3f3225784b741cf4fc18";
        } catch (final UnsupportedEncodingException e) {
            ClientMetrics.INSTANCE.setLastError(null);
            Logger.e(TAG, e.getMessage(), "", OIDCError.ENCODING_IS_NOT_SUPPORTED, e);
            return null;
        } catch (final NoSuchAlgorithmException e) {
            ClientMetrics.INSTANCE.setLastError(null);
            Logger.e(TAG, e.getMessage(), "", OIDCError.ENCODING_IS_NOT_SUPPORTED, e);
            return null;
        }
    }
}
