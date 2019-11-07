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


#import "OIDCAuthorityValidation.h"

#import "OIDCAuthorityCache.h"
#import "OIDCDrsDiscoveryRequest.h"
#import "OIDCAuthorityValidationRequest.h"
#import "OIDCHelpers.h"
#import "OIDCOAuth2Constants.h"
#import "OIDCUserIdentifier.h"
#import "OIDCWebFingerRequest.h"

#import "NSURL+OIDCExtensions.h"

// Trusted relation for webFinger
static NSString* const s_kTrustedRelation              = @"http://schemas.cordovaplugin.com/rel/trusted-realm";

// Trusted authorities
static NSString* const s_kTrustedAuthority             = @"login.windows.net";
static NSString* const s_kTrustedAuthorityUS           = @"login.microsoftonline.us";
static NSString* const s_kTrustedAuthorityChina        = @"login.chinacloudapi.cn";
static NSString* const s_kTrustedAuthorityGermany      = @"login.microsoftonline.de";
static NSString* const s_kTrustedAuthorityWorldWide    = @"login.microsoftonline.com";
static NSString* const s_kTrustedAuthorityUSGovernment = @"login-us.microsoftonline.com";

// OIDC validation check constant
static NSString* const s_kTenantDiscoveryEndpoint      = @"tenant_discovery_endpoint";

// DRS server error message constant
static NSString* const s_kDrsDiscoveryError            = @"DRS discovery was invalid or failed to return PassiveAuthEndpoint";
static NSString* const s_kWebFingerError               = @"WebFinger request was invalid or failed";



@implementation OIDCAuthorityValidation
{
    NSMutableDictionary *_validatedAdfsAuthorities;
    NSSet *_whitelistedOIDCHosts;
    
    dispatch_queue_t _oidcValidationQueue;
}


+ (OIDCAuthorityValidation *)sharedInstance
{
    static OIDCAuthorityValidation *singleton = nil;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        singleton = [[OIDCAuthorityValidation alloc] init];
    });
    
    return singleton;
}

- (id)init
{
    self = [super init];
    if (!self)
    {
        return nil;
    }
    
    _validatedAdfsAuthorities = [NSMutableDictionary new];
    _oidcCache = [OIDCAuthorityCache new];
    
    _whitelistedOIDCHosts = [NSSet setWithObjects:s_kTrustedAuthority, s_kTrustedAuthorityUS,
                            s_kTrustedAuthorityChina, s_kTrustedAuthorityGermany,
                            s_kTrustedAuthorityWorldWide, s_kTrustedAuthorityUSGovernment, nil];
    
    // A serial dispatch queue for all authority validation operations. A very common pattern is for
    // applications to spawn a bunch of threads and call acquireToken on them right at the start. Many
    // of those acquireToken calls will be to the same authority. To avoid making the exact same
    // authority validation network call multiple times we throw the requests in this validation
    // queue.
    _oidcValidationQueue = dispatch_queue_create("oidc.validation.queue", DISPATCH_QUEUE_SERIAL);
    
    return self;
}

#pragma mark - caching
- (BOOL)addValidAuthority:(NSURL *)authority domain:(NSString *)domain
{
    if (!domain || !authority)
    {
        return NO;
    }
    
    // Get authorities for domain (UPN suffix) and create one if needed
    NSMutableSet *authorities = [_validatedAdfsAuthorities objectForKey:domain];
    if (!authorities)
    {
        authorities = [NSMutableSet new];
        [_validatedAdfsAuthorities setObject:authorities forKey:domain];
    }
  
    // Add given authority to trusted set for the domain
    [authorities addObject:authority];
    return YES;
}

- (BOOL)isAuthorityValidated:(NSURL *)authority domain:(NSString *)domain
{
    // Check for authority
    NSSet *authorities = [_validatedAdfsAuthorities objectForKey:domain];
    for (NSURL *url in authorities)
    {
        if([url isEquivalentAuthority:authority])
        {
            return YES;
        }
    }
    return NO;
}

#pragma mark - Authority validation

- (void)checkAuthority:(OIDCRequestParameters*)requestParams
     validateAuthority:(BOOL)validateAuthority
       completionBlock:(OIDCAuthorityValidationCallback)completionBlock
{
    NSString *upn = requestParams.identifier.userId;
    NSString *authority = requestParams.authority;
    
    OIDCAuthenticationError *error = [OIDCHelpers checkAuthority:authority correlationId:requestParams.correlationId];
    if (error)
    {
        completionBlock(NO, error);
        return;
    }
    
    NSURL *authorityURL = [NSURL URLWithString:authority.lowercaseString];
    if (!authorityURL)
    {
        error = [OIDCAuthenticationError errorFromArgument:authority
                                            argumentName:@"authority"
                                           correlationId:requestParams.correlationId];
        completionBlock(NO, error);
        return;
    }
    
    // Check for OIDC or OAUTH
    if ([OIDCHelpers isOAUTHInstanceURL:authorityURL])
    {
        if (!validateAuthority)
        {
            completionBlock(NO, nil);
            return;
        }
        
        // Check for upn suffix
        NSString *upnSuffix = [OIDCHelpers getUPNSuffix:upn];
        if ([NSString adIsStringNilOrBlank:upnSuffix])
        {
            error = [OIDCAuthenticationError errorFromArgument:upnSuffix
                                                argumentName:@"user principal name"
                                               correlationId:requestParams.correlationId];
            completionBlock(NO, error);
            return;
        }
        
        // Validate OAUTH authority
        [self validateOAUTHAuthority:authorityURL
                             domain:upnSuffix
                      requestParams:requestParams
                    completionBlock:completionBlock];
    }
    else
    {
        // Validate OIDC authority
        [self validateOIDCAuthority:authorityURL
                     requestParams:requestParams
                   completionBlock:^(BOOL validated, OIDCAuthenticationError *error)
         {
             if (!validateAuthority && error && [error.protocolCode isEqualToString:@"invalid_instance"])
             {
                 error = nil;
             }
             completionBlock(validated, error);
         }];
    }
}

#pragma mark - OIDC authority validation

// Sends authority validation to the trustedAuthority by leveraging the instance discovery endpoint
// If the authority is known, the server will set the "tenant_discovery_endpoint" parameter in the response.
// The method should be executed on a thread that is guarranteed to exist upon completion, e.g. the UI thread.
- (void)validateOIDCAuthority:(NSURL *)authority
               requestParams:(OIDCRequestParameters *)requestParams
             completionBlock:(OIDCAuthorityValidationCallback)completionBlock
{
    // We first try to get a record from the cache, this will return immediately if it couldn't
    // obtain a read lock
    OIDCAuthorityCacheRecord *record = [_oidcCache tryCheckCache:authority];
    if (record)
    {
        completionBlock(record.validated, record.error);
        return;
    }
    
    // If we wither didn't have a cache, or couldn't get the read lock (which only happens if someone
    // has or is trying to get the write lock) then dispatch onto the OIDC validation queue.
    dispatch_async(_oidcValidationQueue, ^{
        
        // If we didn't have anything in the cache then we need to hold onto the queue until we
        // get a response back from the server, or timeout, or fail for any other reason
        __block dispatch_semaphore_t dsem = dispatch_semaphore_create(0);
        
        [self requestOIDCValidation:authority
                     requestParams:requestParams
                   completionBlock:^(BOOL validated, OIDCAuthenticationError *error)
         {
             
             // Because we're on a serialized queue here to ensure that we don't have more then one
             // validation network request at a time, we want to jump off this queue as quick as
             // possible whenever we hit an error to unblock the queue
             
             dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                 completionBlock(validated, error);
             });
             
             dispatch_semaphore_signal(dsem);
         }];
        
        // We're blocking the OIDC Validation queue here so that we only process one authority validation
        // request at a time. As an application typically only uses a single OIDC authority, this cuts
        // down on the amount of simultaneous requests that go out on multi threaded app launch
        // scenarios.
        if (dispatch_semaphore_wait(dsem, DISPATCH_TIME_NOW) != 0)
        {
            // Only bother logging if we have to wait on the queue.
            OIDC_LOG_INFO(@"Waiting on Authority Validation Queue", requestParams.correlationId, nil);
            dispatch_semaphore_wait(dsem, DISPATCH_TIME_FOREVER);
            OIDC_LOG_INFO(@"Returned from Authority Validation Queue", requestParams.correlationId, nil);
        }
    });
}

- (void)requestOIDCValidation:(NSURL *)authority
               requestParams:(OIDCRequestParameters *)requestParams
             completionBlock:(OIDCAuthorityValidationCallback)completionBlock
{
    // Before we make the request, check the cache again, as these requests happen on a serial queue
    // and it's possible we were waiting on a request that got the information we're looking for.
    OIDCAuthorityCacheRecord *record = [_oidcCache checkCache:authority];
    if (record)
    {
        completionBlock(record.validated, record.error);
        return;
    }
    
    NSString *trustedHost = s_kTrustedAuthorityWorldWide;
    NSString *authorityHost = authority.adHostWithPortIfNecessary;
    if ([_whitelistedOIDCHosts containsObject:authorityHost])
    {
        trustedHost = authorityHost;
    }
    
    [OIDCAuthorityValidationRequest requestMetadataWithAuthority:authority.absoluteString
                                                   trustedHost:trustedHost
                                                       context:requestParams
                                               completionBlock:^(NSDictionary *response, OIDCAuthenticationError *error)
     {
         if (error)
         {
             completionBlock(NO, error);
             return;
         }
         
         NSString *oauthError = response[@"error"];
         if (![NSString adIsStringNilOrBlank:oauthError])
         {
             OIDCAuthenticationError *adError =
             [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                    protocolCode:oauthError
                                                    errorDetails:response[@"error_details"]
                                                   correlationId:requestParams.correlationId];
             
             // If the error is something other than invalid_instance then something wrong is happening
             // on the server.
             if ([oauthError isEqualToString:@"invalid_instance"])
             {
                 [_oidcCache addInvalidRecord:authority oauthError:adError context:requestParams];
             }
             
             completionBlock(NO, adError);
             return;
         }
         
         
         OIDCAuthenticationError *adError = nil;
         if (![_oidcCache processMetadata:response[@"metadata"]
                               authority:authority
                                 context:requestParams
                                   error:&adError])
         {
             completionBlock(NO, adError);
             return;
         }
         
         completionBlock(YES, nil);
     }];
}

#pragma mark - OIDC Authority URL utilities

- (NSURL *)networkUrlForAuthority:(NSURL *)authority
                          context:(id<OIDCRequestContext>)context
{
    if ([OIDCHelpers isOAUTHInstanceURL:authority])
    {
        return authority;
    }
    
    NSURL *url = [_oidcCache networkUrlForAuthority:authority];
    if (!url)
    {
        OIDC_LOG_WARN(@"No cached preferred_network for authority", context.correlationId, nil);
        return authority;
    }
    
    return url;
}

- (NSURL *)cacheUrlForAuthority:(NSURL *)authority
                        context:(id<OIDCRequestContext>)context
{
    if ([OIDCHelpers isOAUTHInstanceURL:authority])
    {
        return authority;
    }
    
    NSURL *url = [_oidcCache cacheUrlForAuthority:authority];
    if (!url)
    {
        OIDC_LOG_WARN(@"No cached preferred_cache for authority", context.correlationId, nil);
        return authority;
    }
    
    
    return url;
}

- (NSArray<NSURL *> *)cacheAliasesForAuthority:(NSURL *)authority
{
    if ([OIDCHelpers isOAUTHInstanceURL:authority])
    {
        return @[ authority ];
    }
    
    return [_oidcCache cacheAliasesForAuthority:authority];
}


- (void)addInvalidAuthority:(NSString *)authority
{
    [_oidcCache addInvalidRecord:[NSURL URLWithString:authority] oauthError:nil context:nil];
}

#pragma mark - OAUTH authority validation
- (void)validateOAUTHAuthority:(NSURL *)authority
                       domain:(NSString *)domain
                requestParams:(OIDCRequestParameters *)requestParams
              completionBlock:(OIDCAuthorityValidationCallback)completionBlock
{
    // Check cache first
    if ([self isAuthorityValidated:authority domain:domain])
    {
        completionBlock(YES, nil);
        return;
    }
    
    // DRS discovery
    [self requestDrsDiscovery:domain
                      context:requestParams
              completionBlock:^(id result, OIDCAuthenticationError *error)
    {
        NSString *passiveAuthEndpoint = [self passiveEndpointFromDRSMetaData:result];

        if (!passiveAuthEndpoint)
        {
            if (!error)
            {
                error = [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                               protocolCode:nil
                                                               errorDetails:s_kDrsDiscoveryError
                                                              correlationId:requestParams.correlationId];
            }
            completionBlock(NO, error);
            return;
        }
        
        [self requestWebFingerValidation:passiveAuthEndpoint
                               authority:authority
                                 context:requestParams
                         completionBlock:^(BOOL validated, OIDCAuthenticationError *error)
        {
            if (validated)
            {
                [self addValidAuthority:authority domain:domain];
            }
            completionBlock(validated, error);
        }];
    }];
}

- (void)requestDrsDiscovery:(NSString *)domain
                    context:(id<OIDCRequestContext>)context
            completionBlock:(void (^)(id result, OIDCAuthenticationError *error))completionBlock
{
    [OIDCDrsDiscoveryRequest requestDrsDiscoveryForDomain:domain
                                               adfsType:OIDC_OAUTH_ON_PREMS
                                                context:context
                                        completionBlock:^(id result, OIDCAuthenticationError *error)
     {
         if (result)
         {
             completionBlock(result, error);
             return;
         }
         
         [OIDCDrsDiscoveryRequest requestDrsDiscoveryForDomain:domain
                                                    adfsType:OIDC_OAUTH_CLOUD
                                                     context:context
                                             completionBlock:^(id result, OIDCAuthenticationError *error)
          {
              completionBlock(result, error);
          }];
     }];
}



- (void)requestWebFingerValidation:(NSString *)passiveAuthEndpoint
                         authority:(NSURL *)authority
                           context:(id<OIDCRequestContext>)context
                   completionBlock:(void (^)(BOOL validated, OIDCAuthenticationError *error))completionBlock
{
    [OIDCWebFingerRequest requestWebFinger:passiveAuthEndpoint
                               authority:authority.absoluteString
                                 context:context
                         completionBlock:^(id result, OIDCAuthenticationError *error)
    {
                             
        BOOL validated = NO;
        if (result)
        {
            validated = [self isRealmTrustedFromWebFingerPayload:result
                                                       authority:authority];
        }
        
        if (!validated && !error)
        {
            error = [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                           protocolCode:nil
                                                           errorDetails:s_kWebFingerError
                                                          correlationId:[context correlationId]];
        }
        completionBlock(validated, error);
    }];
}

#pragma mark - Helper functions

- (NSString *)passiveEndpointFromDRSMetaData:(id)metaData
{
    return [[metaData objectForKey:@"IdentityProviderService"] objectForKey:@"PassiveAuthEndpoint"];
}


- (BOOL)isRealmTrustedFromWebFingerPayload:(id)json
                                 authority:(NSURL *)authority
{
    NSArray *links = [json objectForKey:@"links"];
    for (id link in links)
    {
        NSString *rel = [link objectForKey:@"rel"];
        NSString *target = [link objectForKey:@"href"];

        NSURL *targetURL = [NSURL URLWithString:target];
        
        if ([rel caseInsensitiveCompare:s_kTrustedRelation] == NSOrderedSame &&
            [targetURL isEquivalentAuthority:authority])
        {
            return YES;
        }
    }
    return NO;
}

@end
