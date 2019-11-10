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

#import "OIDCTokenCacheAccessor.h"
#import "OIDCUserIdentifier.h"
#import "OIDCTokenCacheKey.h"
#import "OIDCAuthenticationContext+Internal.h"
#import "OIDCAuthorityValidation.h"
#import "OIDCTokenCacheItem+Internal.h"
#import "OIDCUserInformation.h"
#import "OIDCTelemetry.h"
#import "OIDCTelemetry+Internal.h"
#import "OIDCTelemetryCacheEvent.h"
#import "OIDCTelemetryEventStrings.h"

@implementation OIDCTokenCacheAccessor

+ (NSString*)familyClientId:(NSString*)familyID
{
    if (!familyID)
    {
        familyID = @"1";
    }
    
    return [NSString stringWithFormat:@"foci-%@", familyID];
}

- (id)initWithDataSource:(id<OIDCTokenCacheDataSource>)dataSource
               authority:(NSString *)authority
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _dataSource = dataSource;
    _authority = authority;
    
    return self;
}

- (id<OIDCTokenCacheDataSource>)dataSource
{
    return _dataSource;
}

- (OIDCTokenCacheItem *)getItemForUser:(NSString *)userId
                            resource:(NSString *)resource
                            clientId:(NSString *)clientId
                             context:(id<OIDCRequestContext>)context
                               error:(OIDCAuthenticationError * __autoreleasing *)error
{
    NSArray<NSURL *> *aliases = [[OIDCAuthorityValidation sharedInstance] cacheAliasesForAuthority:[NSURL URLWithString:_authority]];
    for (NSURL *alias in aliases)
    {
        OIDCTokenCacheKey* key = [OIDCTokenCacheKey keyWithAuthority:[alias absoluteString]
                                                        resource:resource
                                                        clientId:clientId
                                                           error:error];
        if (!key)
        {
            return nil;
        }
        
        OIDCAuthenticationError *adError = nil;
        OIDCTokenCacheItem *item = [_dataSource getItemWithKey:key
                                                      userId:userId
                                               correlationId:[context correlationId]
                                                       error:&adError];
        item.storageAuthority = item.authority;
        item.authority = _authority;
        
        if (item)
        {
            return item;
        }
        
        if (adError)
        {
            if (error)
            {
                *error = adError;
            }
            return nil;
        }
    }
    
    return nil;
}

/*!
    Returns a AT/RT Token Cache Item for the given parameters. The RT in this item will only be good
    for the given resource. If no RT is returned in the item then a MRRT or FRT should be used (if
    available).
 */
- (OIDCTokenCacheItem *)getATRTItemForUser:(OIDCUserIdentifier *)identifier
                                resource:(NSString *)resource
                                clientId:(NSString *)clientId
                                 context:(id<OIDCRequestContext>)context
                                   error:(OIDCAuthenticationError * __autoreleasing *)error
{
    [[OIDCTelemetry sharedInstance] startEvent:[context telemetryRequestId] eventName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_LOOKUP];
    
    OIDCTokenCacheItem* item = [self getItemForUser:identifier.userId resource:resource clientId:clientId context:context error:error];
    OIDCTelemetryCacheEvent* event = [[OIDCTelemetryCacheEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_LOOKUP
                                                                       context:context];
    [event setTokenType:OIDC_TELEMETRY_VALUE_ACCESS_TOKEN];
    [event setStatus:item? OIDC_TELEMETRY_VALUE_SUCCEEDED : OIDC_TELEMETRY_VALUE_FAILED];
    [event setSpeInfo:item.speInfo];
    [[OIDCTelemetry sharedInstance] stopEvent:[context telemetryRequestId] event:event];
    return item;
}

/*!
    Returns a Multi-Resource Refresh Token (MRRT) Cache Item for the given parameters. A MRRT can
    potentially be used for many resources for that given user, client ID and authority.
 */
- (OIDCTokenCacheItem *)getMRRTItemForUser:(OIDCUserIdentifier *)identifier
                                clientId:(NSString *)clientId
                                 context:(id<OIDCRequestContext>)context
                                   error:(OIDCAuthenticationError * __autoreleasing *)error
{
    [[OIDCTelemetry sharedInstance] startEvent:[context telemetryRequestId] eventName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_LOOKUP];
    OIDCTokenCacheItem* item = [self getItemForUser:identifier.userId resource:nil clientId:clientId context:context error:error];
    OIDCTelemetryCacheEvent* event = [[OIDCTelemetryCacheEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_LOOKUP
                                                                     requestId:[context telemetryRequestId]
                                                                 correlationId:[context correlationId]];
    [event setTokenType:OIDC_TELEMETRY_VALUE_MULTI_RESOURCE_REFRESH_TOKEN];
    [event setMRRTStatus:OIDC_TELEMETRY_VALUE_NOT_FOUND];
    if (item)
    {
        [event setIsMRRT:OIDC_TELEMETRY_VALUE_YES];
        [event setMRRTStatus:OIDC_TELEMETRY_VALUE_TRIED];
    }
    [event setStatus:item? OIDC_TELEMETRY_VALUE_SUCCEEDED : OIDC_TELEMETRY_VALUE_FAILED];
    [event setSpeInfo:item.speInfo];
    [[OIDCTelemetry sharedInstance] stopEvent:[context telemetryRequestId] event:event];
    return item;
}

/*!
    Returns a Family Refresh Token for the given authority, user and family ID, if available. A FRT can
    be used for many resources within a given family of client IDs.
 */
- (OIDCTokenCacheItem *)getFRTItemForUser:(OIDCUserIdentifier *)identifier
                               familyId:(NSString *)familyId
                                context:(id<OIDCRequestContext>)context
                                  error:(OIDCAuthenticationError * __autoreleasing *)error
{
    [[OIDCTelemetry sharedInstance] startEvent:context.telemetryRequestId eventName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_LOOKUP];
    
    NSString* fociClientId = [OIDCTokenCacheAccessor familyClientId:familyId];
    OIDCTokenCacheItem* item = [self getItemForUser:identifier.userId resource:nil clientId:fociClientId context:context error:error];

    OIDCTelemetryCacheEvent* event = [[OIDCTelemetryCacheEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_LOOKUP
                                                                       context:context];
    [event setTokenType:OIDC_TELEMETRY_VALUE_FAMILY_REFRESH_TOKEN];
    [event setFRTStatus:OIDC_TELEMETRY_VALUE_NOT_FOUND];
    if (item)
    {
        [event setIsFRT:OIDC_TELEMETRY_VALUE_YES];
        [event setFRTStatus:OIDC_TELEMETRY_VALUE_TRIED];
    }
    [event setStatus:item? OIDC_TELEMETRY_VALUE_SUCCEEDED : OIDC_TELEMETRY_VALUE_FAILED];
    [event setSpeInfo:item.speInfo];
    [[OIDCTelemetry sharedInstance] stopEvent:[context telemetryRequestId] event:event];
    return item;
}

- (OIDCTokenCacheItem*)getOAUTHUserTokenForResource:(NSString *)resource
                                        clientId:(NSString *)clientId
                                         context:(id<OIDCRequestContext>)context
                                           error:(OIDCAuthenticationError * __autoreleasing *)error
{
    // OAUTH fix: When talking to OAUTH directly we can get ATs and RTs (but not MRRTs or FRTs) without
    // id tokens. In those cases we do not know who they belong to and cache them with a blank userId
    // (@"").
    
    OIDCTokenCacheKey* key = [OIDCTokenCacheKey keyWithAuthority:_authority
                                                    resource:resource
                                                    clientId:clientId
                                                       error:error];
    if (!key)
    {
        return nil;
    }

    [[OIDCTelemetry sharedInstance] startEvent:[context telemetryRequestId] eventName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_LOOKUP];
    OIDCTokenCacheItem* item = [_dataSource getItemWithKey:key userId:@"" correlationId:[context correlationId] error:error];
    OIDCTelemetryCacheEvent* event = [[OIDCTelemetryCacheEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_LOOKUP
                                                                       context:context];
    [event setTokenType:OIDC_TELEMETRY_VALUE_OAUTH_TOKEN];
    [event setRTStatus:OIDC_TELEMETRY_VALUE_NOT_FOUND];
    if ([item refreshToken])
    {
        [event setIsRT:OIDC_TELEMETRY_VALUE_YES];
        [event setRTStatus:OIDC_TELEMETRY_VALUE_TRIED];
    }
    [event setStatus:item? OIDC_TELEMETRY_VALUE_SUCCEEDED : OIDC_TELEMETRY_VALUE_FAILED];
    [event setSpeInfo:item.speInfo];
    [[OIDCTelemetry sharedInstance] stopEvent:[context telemetryRequestId] event:event];
    return item;
}


//Stores the result in the cache. cacheItem parameter may be nil, if the result is successfull and contains
//the item to be stored.
- (void)updateCacheToResult:(OIDCAuthenticationResult *)result
                  cacheItem:(OIDCTokenCacheItem *)cacheItem
               refreshToken:(NSString *)refreshToken
                    context:(id<OIDCRequestContext>)context
{
    
    if(!result)
    {
        return;
    }
    
    if (OIDC_SUCCEEDED == result.status)
    {
        OIDCTokenCacheItem* item = [result tokenCacheItem];
        
        // Validate that this item is a valid item to add.
        if(![OIDCAuthenticationContext handleNilOrEmptyAsResult:item argumentName:@"tokenCacheItem" authenticationResult:&result]
           || ![OIDCAuthenticationContext handleNilOrEmptyAsResult:item argumentName:@"resource" authenticationResult:&result]
           || ![OIDCAuthenticationContext handleNilOrEmptyAsResult:item argumentName:@"accessToken" authenticationResult:&result])
        {
            OIDC_LOG_WARN(@"Told to update cache to an invalid token cache item", [context correlationId], nil);
            return;
        }
        
        [self updateCacheToItem:item
                           MRRT:[result multiResourceRefreshToken]
                        context:context];
        return;
    }
    
    if (result.error.code != OIDC_ERROR_SERVER_REFRESH_TOKEN_REJECTED)
    {
        return;
    }
    
    // Only remove tokens from the cache if we get an invalid_grant from the server
    if (![result.error.protocolCode isEqualToString:@"invalid_grant"])
    {
        return;
    }
    
    [self removeItemFromCache:cacheItem
                 refreshToken:refreshToken
                      context:context
                        error:result.error];
}

- (void)updateCacheToItem:(OIDCTokenCacheItem *)cacheItem
                     MRRT:(BOOL)isMRRT
                  context:(id<OIDCRequestContext>)context
{
    NSUUID* correlationId = [context correlationId];
    NSString* telemetryRequestId = [context telemetryRequestId];
    
    NSString* savedRefreshToken = cacheItem.refreshToken;
    if (isMRRT)
    {
        OIDC_LOG_VERBOSE_F(@"Token cache store", correlationId, @"Storing multi-resource refresh token for authority: %@", _authority);
        [[OIDCTelemetry sharedInstance] startEvent:telemetryRequestId eventName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_WRITE];
        
        //If the server returned a multi-resource refresh token, we break
        //the item into two: one with the access token and no refresh token and
        //another one with the broad refresh token and no access token and no resource.
        //This breaking is useful for further updates on the cache and quick lookups
        OIDCTokenCacheItem* multiRefreshTokenItem = [cacheItem copy];
        cacheItem.refreshToken = nil;
        
        multiRefreshTokenItem.accessToken = nil;
        multiRefreshTokenItem.resource = nil;
        multiRefreshTokenItem.expiresOn = nil;
        [self addOrUpdateItem:multiRefreshTokenItem context:context error:nil];
        OIDCTelemetryCacheEvent* event = [[OIDCTelemetryCacheEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_WRITE
                                                                           context:context];
        [event setIsMRRT:OIDC_TELEMETRY_VALUE_YES];
        [event setTokenType:OIDC_TELEMETRY_VALUE_MULTI_RESOURCE_REFRESH_TOKEN];
        [event setSpeInfo:multiRefreshTokenItem.speInfo];
        [[OIDCTelemetry sharedInstance] stopEvent:telemetryRequestId event:event];
        
        // If the item is also a Family Refesh Token (FRT) we update the FRT
        // as well so we have a guaranteed spot to look for the most recent FRT.
        NSString* familyId = cacheItem.familyId;
        if (familyId)
        {
            [[OIDCTelemetry sharedInstance] startEvent:telemetryRequestId eventName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_WRITE];
            
            OIDCTokenCacheItem* frtItem = [multiRefreshTokenItem copy];
            NSString* fociClientId = [OIDCTokenCacheAccessor familyClientId:familyId];
            frtItem.clientId = fociClientId;
            [self addOrUpdateItem:frtItem context:context error:nil];
            
            OIDCTelemetryCacheEvent* event = [[OIDCTelemetryCacheEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_WRITE
                                                                               context:context];
            [event setIsFRT:OIDC_TELEMETRY_VALUE_YES];
            [event setTokenType:OIDC_TELEMETRY_VALUE_FAMILY_REFRESH_TOKEN];
            [event setSpeInfo:frtItem.speInfo];
            [[OIDCTelemetry sharedInstance] stopEvent:telemetryRequestId event:event];
        }
    }
    
    OIDC_LOG_VERBOSE_F(@"Token cache store", correlationId, @"Storing access token for resource: %@", cacheItem.resource);
    [[OIDCTelemetry sharedInstance] startEvent:telemetryRequestId eventName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_WRITE];
    [self addOrUpdateItem:cacheItem context:context error:nil];
    cacheItem.refreshToken = savedRefreshToken;//Restore for the result
    OIDCTelemetryCacheEvent* event = [[OIDCTelemetryCacheEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_WRITE
                                                                       context:context];
    [event setTokenType:OIDC_TELEMETRY_VALUE_ACCESS_TOKEN];
    [event setSpeInfo:cacheItem.speInfo];
    [[OIDCTelemetry sharedInstance] stopEvent:telemetryRequestId event:event];
}

- (BOOL)addOrUpdateItem:(nonnull OIDCTokenCacheItem *)item
                context:(id<OIDCRequestContext>)context
                  error:(OIDCAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    NSURL *oldAuthority = [NSURL URLWithString:item.authority];
    NSURL *newAuthority = [[OIDCAuthorityValidation sharedInstance] cacheUrlForAuthority:oldAuthority context:context];
    
    // The authority used to retrieve the item over the network can differ from the preferred authority used to
    // cache the item. As it would be awkward to cache an item using an authority other then the one we store
    // it with we switch it out before saving it to cache.
    item.authority = [newAuthority absoluteString];
    BOOL ret = [_dataSource addOrUpdateItem:item correlationId:context.correlationId error:error];
    item.authority = [oldAuthority absoluteString];
    
    return ret;
}

- (void)removeItemFromCache:(OIDCTokenCacheItem *)cacheItem
               refreshToken:(NSString *)refreshToken
                    context:(id<OIDCRequestContext>)context
                      error:(OIDCAuthenticationError *)error
{
    if (!cacheItem && !refreshToken)
    {
        return;
    }
    
    
    OIDCTelemetryCacheEvent* event = [[OIDCTelemetryCacheEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_DELETE
                                                                       context:context];
    [event setSpeInfo:cacheItem.speInfo];
    [[OIDCTelemetry sharedInstance] startEvent:[context telemetryRequestId] eventName:OIDC_TELEMETRY_EVENT_TOKEN_CACHE_DELETE];
    [self removeImpl:cacheItem refreshToken:refreshToken context:context error:error];
    [[OIDCTelemetry sharedInstance] stopEvent:[context telemetryRequestId] event:event];
}

- (void)removeImpl:(OIDCTokenCacheItem *)cacheItem
      refreshToken:(NSString *)refreshToken
           context:(id<OIDCRequestContext>)context
             error:(OIDCAuthenticationError *)error
{
    //The refresh token didn't work. We need to tombstone this refresh item in the cache.
    OIDCTokenCacheKey* cacheKey = [cacheItem extractKey:nil];
    if (!cacheKey)
    {
        return;
    }
    
    NSUUID* correlationId = [context correlationId];
    
    OIDCTokenCacheItem* existing = [_dataSource getItemWithKey:cacheKey
                                                      userId:cacheItem.userInformation.userId
                                               correlationId:correlationId
                                                       error:nil];
    if (!existing)
    {
        existing = [_dataSource getItemWithKey:[cacheKey mrrtKey]
                                        userId:cacheItem.userInformation.userId
                                 correlationId:correlationId
                                         error:nil];
    }
    
    if (!existing || ![refreshToken isEqualToString:existing.refreshToken])
    {
        return;
    }
    
    OIDC_LOG_VERBOSE_F(@"Token cache store", correlationId, @"Tombstoning cache for resource: %@", cacheItem.resource);
    //update tombstone property before update the tombstone in cache
    [existing makeTombstone:@{ @"correlationId" : [correlationId UUIDString],
                               @"errorDetails" : [error errorDetails],
                               @"protocolCode" : [error protocolCode] }];
    [_dataSource addOrUpdateItem:existing correlationId:correlationId error:nil];
}

@end
