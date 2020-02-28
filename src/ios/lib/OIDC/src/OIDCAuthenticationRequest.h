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


#import <Foundation/Foundation.h>
#import "OIDCAuthenticationContext.h"
#import "OIDCRequestParameters.h"

@class OIDCUserIdentifier;
@class OIDCTokenCacheAccessor;

#define OIDC_REQUEST_CHECK_ARGUMENT(_arg) { \
    if (!_arg || ([_arg isKindOfClass:[NSString class]] && [(NSString*)_arg isEqualToString:@""])) { \
        NSString* _details = @#_arg " must not be nil!"; \
        completionBlock([OIDCAuthenticationResult resultFromParameterError:_details]); \
        return; \
    } \
}

#define OIDC_REQUEST_CHECK_PROPERTY(_property) { \
    if (!_property || ([_property isKindOfClass:[NSString class]] && [(NSString*)_property isEqualToString:@""])) { \
        NSString* _details = @#_property " must not be nil!";\
        completionBlock([OIDCAuthenticationResult resultFromParameterError:_details]); \
        return; \
    } \
}

@interface OIDCAuthenticationRequest : NSObject <OIDCRequestContext>
{
@protected
    OIDCAuthenticationContext* _context;
    OIDCRequestParameters* _requestParams;
    
    OIDCPromptBehavior _promptBehavior;
    
    NSString* _scope;
    NSString* _queryParams;
    NSString* _claims;
    
    NSString* _refreshTokenCredential;
    
    NSString* _samlAssertion;
    OIDCAssertionType _assertionType;
    
    BOOL _silent;
    BOOL _allowSilent;
    BOOL _skipCache;
    
    NSString* _logComponent;
    
    BOOL _requestStarted;
    BOOL _attemptedFRT;
    
    OIDCTokenCacheItem* _mrrtItem;
    
    OIDCAuthenticationError* _underlyingError;
}

@property (retain) NSString* logComponent;

// These constructors exists *solely* to be used when trying to use some of the caching logic.
// You can't actually send requests with it. They will fail.
+ (OIDCAuthenticationRequest *)requestWithAuthority:(NSString *)authority
                                      tokenEndpoint:(NSString *)tokenEndpoint
                                       responseType:(NSString *)responseType;

+ (OIDCAuthenticationRequest *)requestWithContext:(OIDCAuthenticationContext *)context;

// The default constructor. For requestParams, redirectUri, clientId and resource are mandatory
+ (OIDCAuthenticationRequest*)requestWithContext:(OIDCAuthenticationContext*)context
                                 requestParams:(OIDCRequestParameters*)requestParams
                                         error:(OIDCAuthenticationError* __autoreleasing *)error;

// This message is sent before any stage of processing is done, it marks all the fields as un-editable and grabs the
// correlation ID from the logger
- (void)ensureRequest;

// These can only be set before the request gets sent out.
- (void)setScope:(NSString*)scope;
- (void)setExtraQueryParameters:(NSString*)queryParams;
- (void)setClaims:(NSString *)claims;
- (void)setUserIdentifier:(OIDCUserIdentifier*)identifier;
- (void)setUserId:(NSString*)userId;
- (void)setPromptBehavior:(OIDCPromptBehavior)promptBehavior;
- (void)setSilent:(BOOL)silent;
- (void)setSkipCache:(BOOL)skipCache;
- (void)setCorrelationId:(NSUUID*)correlationId;
- (NSUUID*)correlationId;
- (NSString*)telemetryRequestId;
- (OIDCRequestParameters*)requestParams;
#if OIDC_BROKER
- (NSString*)redirectUri;
- (void)setRedirectUri:(NSString*)redirectUri;
- (void)setAllowSilentRequests:(BOOL)allowSilent;
- (void)setRefreshTokenCredential:(NSString*)refreshTokenCredential;
#endif
- (void)setSamlAssertion:(NSString*)samlAssertion;
- (void)setAssertionType:(OIDCAssertionType)assertionType;

/*!
    Takes the UI interaction lock for the current request, will send an error
    to completionBlock if it fails.
 
    @param completionBlock  the OIDCAuthenticationCallback to send an error to if
                            one occurs.
 
    @return NO if we fail to take the exclusion lock
 */
- (BOOL)takeExclusionLock:(OIDCAuthenticationCallback)completionBlock;

/*!
    Releases the exclusion lock
 */
+ (void)releaseExclusionLock;

/*!
    The current interactive request OIDC is displaying UI for (if any)
 */
+ (OIDCAuthenticationRequest*)currentModalRequest;

@end

#import "OIDCAuthenticationRequest+AcquireAssertion.h"
#import "OIDCAuthenticationRequest+AcquireToken.h"
#import "OIDCAuthenticationRequest+Broker.h"
#import "OIDCAuthenticationRequest+WebRequest.h"
