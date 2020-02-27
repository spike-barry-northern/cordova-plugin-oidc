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


#import "OIDC_Internal.h"
#import "OIDCAuthenticationRequest.h"
#import "OIDCAuthorityValidation.h"
#import "OIDCAuthenticationResult+Internal.h"
#import "OIDCAuthenticationContext+Internal.h"
#import "NSDictionary+OIDCExtensions.h"
#import "NSString+OIDCHelperMethods.h"
#import "NSURL+OIDCExtensions.h"
#import "OIDCTelemetry.h"
#import "OIDCTelemetry+Internal.h"

#if TARGET_OS_IPHONE
#import "OIDCBrokerKeyHelper.h"
#endif

#import "OIDCAuthenticationRequest+WebRequest.h"
#import "OIDCUserIdentifier.h"

#include <libkern/OSAtomic.h>

static OIDCAuthenticationRequest* s_modalRequest = nil;
static dispatch_semaphore_t s_interactionLock = nil;

@implementation OIDCAuthenticationRequest

@synthesize logComponent = _logComponent;

#define RETURN_IF_NIL(_X) { if (!_X) { OIDC_LOG_ERROR(@#_X " must not be nil!", OIDC_FAILED, nil, nil); return nil; } }
#define ERROR_RETURN_IF_NIL(_X) { \
    if (!_X) { \
        if (error) { \
            *error = [OIDCAuthenticationError errorFromArgument:_X argumentName:@#_X correlationId:context.correlationId]; \
        } \
        return nil; \
    } \
}

+ (void)initialize
{
    s_interactionLock = dispatch_semaphore_create(1);
}

+ (OIDCAuthenticationRequest *)requestWithAuthority:(NSString *)authority
                                      tokenEndpoint:(NSString *)tokenEndpoint
                                       responseType:(NSString *)responseType
{
    OIDCAuthenticationContext* context = [[OIDCAuthenticationContext alloc] initWithAuthority:authority
                                                                                tokenEndpoint:tokenEndpoint
                                                                                 responseType:responseType
                                                                            validateAuthority:NO error:nil];
    
    return [self requestWithContext:context];
}

+ (OIDCAuthenticationRequest *)requestWithContext:(OIDCAuthenticationContext *)context
{
    OIDCAuthenticationRequest* request = [[OIDCAuthenticationRequest alloc] init];
    if (!request)
    {
        return nil;
    }
    
    request->_context = context;
    
    return request;
}

+ (OIDCAuthenticationRequest*)requestWithContext:(OIDCAuthenticationContext*)context
                                 requestParams:(OIDCRequestParameters*)requestParams
                                         error:(OIDCAuthenticationError* __autoreleasing *)error
{
    ERROR_RETURN_IF_NIL(context);
    ERROR_RETURN_IF_NIL([requestParams clientId]);
    
    OIDCAuthenticationRequest *request = [[OIDCAuthenticationRequest alloc] initWithContext:context requestParams:requestParams];
    return request;
}

- (id)initWithContext:(OIDCAuthenticationContext*)context
        requestParams:(OIDCRequestParameters*)requestParams
{
    RETURN_IF_NIL(context);
    RETURN_IF_NIL([requestParams clientId]);
    
    if (!(self = [super init]))
        return nil;
    
    _context = context;
    _requestParams = requestParams;
    
    _promptBehavior = OIDC_PROMPT_AUTO;
    
    // This line is here to suppress a analyzer warning, has no effect
    _allowSilent = NO;
    _skipCache = NO;
    
    return self;
}

#define CHECK_REQUEST_STARTED { \
    if (_requestStarted) { \
        NSString* _details = [NSString stringWithFormat:@"call to %s after the request started. call has no effect.", __PRETTY_FUNCTION__]; \
        OIDC_LOG_WARN(_details, nil, nil); \
        return; \
    } \
}

- (void)setScope:(NSString *)scope
{
    CHECK_REQUEST_STARTED;
    if (_scope == scope)
    {
        return;
    }
    _scope = [scope copy];
}

- (void)setExtraQueryParameters:(NSString *)queryParams
{
    CHECK_REQUEST_STARTED;
    if (_queryParams == queryParams)
    {
        return;
    }
    _queryParams = [queryParams copy];
}

- (void)setClaims:(NSString *)claims
{
    CHECK_REQUEST_STARTED;
    if (_claims == claims)
    {
        return;
    }
    _claims = [claims copy];
}

- (void)setUserIdentifier:(OIDCUserIdentifier *)identifier
{
    CHECK_REQUEST_STARTED;
    if ([_requestParams identifier] == identifier)
    {
        return;
    }
    [_requestParams setIdentifier:identifier];
}

- (void)setUserId:(NSString *)userId
{
    CHECK_REQUEST_STARTED;
    [self setUserIdentifier:[OIDCUserIdentifier identifierWithId:userId]];
}

- (void)setPromptBehavior:(OIDCPromptBehavior)promptBehavior
{
    CHECK_REQUEST_STARTED;
    _promptBehavior = promptBehavior;
}

- (void)setSilent:(BOOL)silent
{
    CHECK_REQUEST_STARTED;
    _silent = silent;
}

- (void)setSkipCache:(BOOL)skipCache
{
    CHECK_REQUEST_STARTED;
    _skipCache = skipCache;
}

- (void)setCorrelationId:(NSUUID*)correlationId
{
    CHECK_REQUEST_STARTED;
    if ([_requestParams correlationId] == correlationId)
    {
        return;
    }
    [_requestParams setCorrelationId:correlationId];
}

#if OIDC_BROKER

- (NSString*)redirectUri
{
    return _requestParams.redirectUri;
}

- (void)setRedirectUri:(NSString *)redirectUri
{
    // We knowingly do this mid-request when we have to change auth types
    // Thus no CHECK_REQUEST_STARTED
    [_requestParams setRedirectUri:redirectUri];
}

- (void)setAllowSilentRequests:(BOOL)allowSilent
{
    CHECK_REQUEST_STARTED;
    _allowSilent = allowSilent;
}

- (void)setRefreshTokenCredential:(NSString*)refreshTokenCredential
{
    CHECK_REQUEST_STARTED;
    if (_refreshTokenCredential == refreshTokenCredential)
    {
        return;
    }
    _refreshTokenCredential = [refreshTokenCredential copy];
}
#endif

- (void)setSamlAssertion:(NSString *)samlAssertion
{
    CHECK_REQUEST_STARTED;
    if (_samlAssertion == samlAssertion)
    {
        return;
    }
    _samlAssertion = [samlAssertion copy];
}

- (void)setAssertionType:(OIDCAssertionType)assertionType
{
    CHECK_REQUEST_STARTED;
    
    _assertionType = assertionType;
}

- (void)ensureRequest
{
    if (_requestStarted)
    {
        return;
    }
    
    [self correlationId];
    [self telemetryRequestId];
    
    _requestStarted = YES;
}

- (NSUUID*)correlationId
{
    if ([_requestParams correlationId] == nil)
    {
        //if correlationId is set in context, use it
        //if not, generate one
        if ([_context correlationId])
        {
            [_requestParams setCorrelationId:[_context correlationId]];
        } else {
            [_requestParams setCorrelationId:[NSUUID UUID]];
        }
    }
    
    return [_requestParams correlationId];
}

- (NSString*)telemetryRequestId
{
    if ([_requestParams telemetryRequestId] == nil)
    {
        [_requestParams setTelemetryRequestId:[[OIDCTelemetry sharedInstance] registerNewRequest]];
    }
    
    return [_requestParams telemetryRequestId];
}

- (OIDCRequestParameters*)requestParams
{
    return _requestParams;
}

/*!
    Takes the UI interaction lock for the current request, will send an error
    to completionBlock if it fails.
 
    @param completionBlock  the OIDCAuthenticationCallback to send an error to if
                            one occurs.
 
    @return NO if we fail to take the exclusion lock
 */
- (BOOL)takeExclusionLock:(OIDCAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    if (dispatch_semaphore_wait(s_interactionLock, DISPATCH_TIME_NOW) != 0)
    {
        NSString* message = @"The user is currently prompted for credentials as result of another acquireToken request. Please retry the acquireToken call later.";
        OIDCAuthenticationError* error = [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_UI_MULTLIPLE_INTERACTIVE_REQUESTS
                                                                              protocolCode:nil
                                                                              errorDetails:message
                                                                             correlationId:_requestParams.correlationId];
        completionBlock([OIDCAuthenticationResult resultFromError:error]);
        return NO;
    }
    
    s_modalRequest = self;
    return YES;
}

/*!
    Releases the exclusion lock
 */
+ (void)releaseExclusionLock
{
    dispatch_semaphore_signal(s_interactionLock);
    s_modalRequest = nil;
}

+ (OIDCAuthenticationRequest*)currentModalRequest
{
    return s_modalRequest;
}

@end
