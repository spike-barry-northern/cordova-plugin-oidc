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

#import "OIDCAuthenticationSettings.h"
#import "OIDCTokenCache+Internal.h"
#import "OIDCRequestParameters.h"
#if TARGET_OS_IPHONE
#import "OIDCKeychainTokenCache+Internal.h"
#endif 

#import "OIDCAuthenticationContext+Internal.h"
#import "OIDCTelemetry.h"
#import "OIDCTelemetry+Internal.h"
#import "OIDCTelemetryAPIEvent.h"
#import "OIDCTelemetryEventStrings.h"
#import "OIDCUserIdentifier.h"
#import "OIDCTokenCacheItem.h"

typedef void(^OIDCAuthorizationCodeCallback)(NSString*, OIDCAuthenticationError*);

// This variable is purposefully a global so that way we can more easily pull it out of the
// symbols in a binary to detect what version of OIDC is being used without needing to
// run the application.
NSString* OIDC_VERSION_VAR = @OIDC_VERSION_STRING;

@implementation OIDCAuthenticationContext

@synthesize authority = _authority;
@synthesize validateAuthority = _validateAuthority;
@synthesize correlationId = _correlationId;
@synthesize credentialsType = _credentialsType;
@synthesize extendedLifetimeEnabled = _extendedLifetimeEnabled;
@synthesize logComponent = _logComponent;
@synthesize webView = _webView;

+ (void)load
{
    // +load is called by the ObjC runtime before main() as it loads in ObjC symbols and
    // populates the runtime.
    
    NSLog(@"OIDC version %@", OIDC_VERSION_VAR);
}

- (id)init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

#if TARGET_OS_IPHONE
- (id)initWithAuthority:(NSString*) authority
      validateAuthority:(BOOL)bValidate
            sharedGroup:(NSString*)sharedGroup
                  error:(OIDCAuthenticationError* __autoreleasing *) error
{
    API_ENTRY;
    if (!(self = [self initWithAuthority:authority validateAuthority:bValidate error:error]))
    {
        return nil;
    }
    
    [self setTokenCacheStore:[OIDCKeychainTokenCache keychainCacheForGroup:sharedGroup]];
    
    return self;
}
#endif

- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
          cacheDelegate:(id<OIDCTokenCacheDelegate>) delegate
                  error:(OIDCAuthenticationError * __autoreleasing *)error
{
    API_ENTRY;
    if (!(self = [self initWithAuthority:authority validateAuthority:validateAuthority error:error]))
    {
        return nil;
    }
    
    OIDCTokenCache* cache = [OIDCTokenCache new];
    [cache setDelegate:delegate];
    
    [self setTokenCacheStore:cache];
    return self;
}

- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
                  error:(OIDCAuthenticationError *__autoreleasing *)error
{
    id<OIDCTokenCacheDataSource> tokenCache = nil;

#if TARGET_OS_IPHONE
    tokenCache = [OIDCKeychainTokenCache defaultKeychainCache];
    if (!tokenCache)
    {
        OIDCAuthenticationError* adError = [OIDCAuthenticationError unexpectedInternalError:@"Unable to get kecyhain token cache" correlationId:nil];
        if (error)
        {
            *error = adError;
        }
        return nil;
    }
#else
    tokenCache = [OIDCTokenCache defaultCache];
#endif
    
    return [self initWithAuthority:authority
                 validateAuthority:validateAuthority
                        tokenCache:tokenCache
                             error:error];
}

- (OIDCAuthenticationRequest*)requestWithRedirectString:(NSString*)redirectUri
                                             clientId:(NSString*)clientId
                                             resource:(NSString*)resource
                                      completionBlock:(OIDCAuthenticationCallback)completionBlock

{
    OIDCAuthenticationError* error = nil;
    
    OIDCRequestParameters* requestParams = [[OIDCRequestParameters alloc] init];
    [requestParams setAuthority:_authority];
    [requestParams setResource:resource];
    [requestParams setClientId:clientId];
    [requestParams setRedirectUri:redirectUri];
    [requestParams setTokenCache:_tokenCacheStore];
    [requestParams setExtendedLifetime:_extendedLifetimeEnabled];

    OIDCAuthenticationRequest* request = [OIDCAuthenticationRequest requestWithContext:self
                                                                     requestParams:requestParams
                                                                             error:&error];
    
    if (!request)
    {
        completionBlock([OIDCAuthenticationResult resultFromError:error correlationId:_correlationId]);
    }
    
    return request;
}

- (OIDCAuthenticationRequest*)requestWithRedirectUrl:(NSURL*)redirectUri
                                          clientId:(NSString*)clientId
                                          resource:(NSString*)resource
                                   completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    return [self requestWithRedirectString:[redirectUri absoluteString]
                                  clientId:clientId
                                  resource:resource
                           completionBlock:completionBlock];
}

+ (OIDCAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                                         error:(OIDCAuthenticationError* __autoreleasing *)error
{
    API_ENTRY;
    return [self authenticationContextWithAuthority:authority
                                  validateAuthority:YES
                                              error:error];
}

+ (OIDCAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                             validateAuthority:(BOOL)bValidate
                                                         error:(OIDCAuthenticationError* __autoreleasing *)error
{
    API_ENTRY
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(authority);
    
    OIDCAuthenticationContext* context = [[OIDCAuthenticationContext alloc] initWithAuthority:authority
                                                                        validateAuthority:bValidate
                                                                                    error:error];
    if (!context)
    {
        
        return nil;
    }
    return context;
}

#if TARGET_OS_IPHONE
+ (OIDCAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                                   sharedGroup:(NSString*)sharedGroup
                                                         error:(OIDCAuthenticationError* __autoreleasing *)error
{
    API_ENTRY;
    return [self authenticationContextWithAuthority:authority
                                  validateAuthority:YES
                                        sharedGroup:sharedGroup
                                              error:error];
}

+ (OIDCAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                             validateAuthority:(BOOL)bValidate
                                                   sharedGroup:(NSString*)sharedGroup
                                                         error:(OIDCAuthenticationError* __autoreleasing *)error
{
    API_ENTRY;
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(authority);
    
    return [[self alloc] initWithAuthority:authority
                         validateAuthority:bValidate
                               sharedGroup:sharedGroup
                                     error:error];
}
#endif // TARGET_OS_IPHONE

+ (BOOL)isResponseFromBroker:(NSString *)sourceApplication
                    response:(NSURL *)response
{
    return response && [sourceApplication isEqualToString:OIDC_BROKER_APP_BUNDLE_ID];
}

+ (BOOL)handleBrokerResponse:(NSURL*)response
{
    return [OIDCAuthenticationRequest internalHandleBrokerResponse:response];
}

#define REQUEST_WITH_REDIRECT_STRING(_redirect, _clientId, _resource) \
    THROW_ON_NIL_ARGUMENT(completionBlock) \
    CHECK_STRING_ARG_BLOCK(_clientId) \
    OIDCAuthenticationRequest* request = [self requestWithRedirectString:_redirect clientId:_clientId resource:_resource completionBlock:completionBlock]; \
    if (!request) { return; } \
    [request setLogComponent:_logComponent];

#define REQUEST_WITH_REDIRECT_URL(_redirect, _clientId, _resource) \
    THROW_ON_NIL_ARGUMENT(completionBlock) \
    CHECK_STRING_ARG_BLOCK(_clientId) \
    OIDCAuthenticationRequest* request = [self requestWithRedirectUrl:_redirect clientId:_clientId resource:_resource completionBlock:completionBlock]; \
    if (!request) { return; } \
    [request setLogComponent:_logComponent];

#define CHECK_STRING_ARG_BLOCK(_arg) \
    if ([NSString adIsStringNilOrBlank:_arg]) { \
        OIDCAuthenticationError* error = [OIDCAuthenticationError invalidArgumentError:@#_arg " cannot be nil" correlationId:_correlationId]; \
        completionBlock([OIDCAuthenticationResult resultFromError:error correlationId:_correlationId]); \
        return; \
    }

- (void)acquireTokenForAssertion:(NSString*)assertion
                   assertionType:(OIDCAssertionType)assertionType
                        resource:(NSString*)resource
                        clientId:(NSString*)clientId
                          userId:(NSString*)userId
                 completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_STRING(nil, clientId, resource);
    CHECK_STRING_ARG_BLOCK(assertion);
    CHECK_STRING_ARG_BLOCK(resource);
    
    [request setUserId:userId];
    [request setSamlAssertion:assertion];
    [request setAssertionType:assertionType];
    
    [request acquireToken:@"6" completionBlock:completionBlock];
    
}


- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                 completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request acquireToken:@"118" completionBlock:completionBlock];
}

- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                          userId:(NSString*)userId
                 completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setUserId:userId];
    
    [request acquireToken:@"121" completionBlock:completionBlock];
}

- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                          userId:(NSString*)userId
            extraQueryParameters:(NSString*)queryParams
                 completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setUserId:userId];
    [request setExtraQueryParameters:queryParams];
    
    [request acquireToken:@"124" completionBlock:completionBlock];
}

- (void)acquireTokenSilentWithResource:(NSString*)resource
                              clientId:(NSString*)clientId
                           redirectUri:(NSURL*)redirectUri
                       completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setSilent:YES];
    [request acquireToken:@"7" completionBlock:completionBlock];
}

- (void)acquireTokenSilentWithResource:(NSString*)resource
                              clientId:(NSString*)clientId
                           redirectUri:(NSURL*)redirectUri
                                userId:(NSString*)userId
                       completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setUserId:userId];
    [request setSilent:YES];
    [request acquireToken:@"8" completionBlock:completionBlock];
}

- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                  promptBehavior:(OIDCPromptBehavior)promptBehavior
                          userId:(NSString*)userId
            extraQueryParameters:(NSString*)queryParams
                 completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setUserId:userId];
    [request setPromptBehavior:promptBehavior];
    [request setExtraQueryParameters:queryParams];
    [request acquireToken:@"127" completionBlock:completionBlock];
}

- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                  promptBehavior:(OIDCPromptBehavior)promptBehavior
                  userIdentifier:(OIDCUserIdentifier*)userId
            extraQueryParameters:(NSString*)queryParams
                 completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setPromptBehavior:promptBehavior];
    [request setUserIdentifier:userId];
    [request setExtraQueryParameters:queryParams];
    [request acquireToken:@"130" completionBlock:completionBlock];
}

- (void)acquireTokenWithResource:(NSString *)resource
                        clientId:(NSString *)clientId
                     redirectUri:(NSURL *)redirectUri
                  promptBehavior:(OIDCPromptBehavior)promptBehavior
                  userIdentifier:(OIDCUserIdentifier *)userId
            extraQueryParameters:(NSString *)queryParams
                          claims:(NSString *)claims
                 completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setPromptBehavior:promptBehavior];
    [request setUserIdentifier:userId];
    [request setExtraQueryParameters:queryParams];
    [request setClaims:claims];
    [request acquireToken:@"133" completionBlock:completionBlock];
}

@end

@implementation OIDCAuthenticationContext (CacheStorage)

- (void)setTokenCacheStore:(id<OIDCTokenCacheDataSource>)dataSource
{
    if (_tokenCacheStore.dataSource == dataSource)
    {
        return;
    }
    
    _tokenCacheStore = [[OIDCTokenCacheAccessor alloc] initWithDataSource:dataSource authority:_authority];
}

- (OIDCTokenCacheAccessor *)tokenCacheStore
{
    return _tokenCacheStore;
}

@end

