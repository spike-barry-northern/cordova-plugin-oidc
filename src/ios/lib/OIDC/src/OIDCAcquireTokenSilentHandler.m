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


#import "OIDCAcquireTokenSilentHandler.h"
#import "OIDCTokenCacheKey.h"
#import "OIDCTokenCacheItem+Internal.h"
#import "OIDCUserIdentifier.h"
#import "OIDCOAuth2Constants.h"
#import "OIDCAuthenticationContext+Internal.h"
#import "OIDCUserInformation.h"
#import "OIDCWebAuthRequest.h"
#import "OIDCHelpers.h"
#import "OIDCTokenCacheAccessor.h"
#import "OIDCTelemetry.h"
#import "OIDCTelemetry+Internal.h"
#import "OIDCTelemetryAPIEvent.h"
#import "OIDCTelemetryEventStrings.h"
#import "OIDCRequestParameters.h"

@implementation OIDCAcquireTokenSilentHandler

+ (OIDCAcquireTokenSilentHandler *)requestWithParams:(OIDCRequestParameters*)requestParams
{
    OIDCAcquireTokenSilentHandler* handler = [OIDCAcquireTokenSilentHandler new];
    
    // As this is an internal class these properties should all be set by the
    // authentication request, which created copies of them.
    
    handler->_requestParams = requestParams;
    
    return handler;
}

- (void)getToken:(OIDCAuthenticationCallback)completionBlock
{
    [self getAccessToken:^(OIDCAuthenticationResult *result)
     {
         // Logic for returning extended lifetime token
         if ([_requestParams extendedLifetime] && [self isServerUnavailable:result] && _extendedLifetimeAccessTokenItem)
         {
             _extendedLifetimeAccessTokenItem.expiresOn =
             [_extendedLifetimeAccessTokenItem.additionalServer valueForKey:@"ext_expires_on"];
             
             // give the stale token as result
             [OIDCLogger logToken:_extendedLifetimeAccessTokenItem.accessToken
                      tokenType:@"AT (extended lifetime)"
                      expiresOn:_extendedLifetimeAccessTokenItem.expiresOn
                        context:@"Returning"
                  correlationId:_requestParams.correlationId];
             
             result = [OIDCAuthenticationResult resultFromTokenCacheItem:_extendedLifetimeAccessTokenItem
                                             multiResourceRefreshToken:NO
                                                         correlationId:[_requestParams correlationId]];
             [result setExtendedLifeTimeToken:YES];
         }
         
         completionBlock(result);
     }];
}

#pragma mark -
#pragma mark Refresh Token Helper Methods

//Obtains an access token from the passed refresh token. If "cacheItem" is passed, updates it with the additional
//information and updates the cache:
- (void)acquireTokenByRefreshToken:(NSString*)refreshToken
                         cacheItem:(OIDCTokenCacheItem*)cacheItem
                   completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    [OIDCLogger logToken:refreshToken
             tokenType:@"RT"
             expiresOn:nil
               context:[NSString stringWithFormat:@"Attempting to acquire for %@ using", _requestParams.resource]
         correlationId:_requestParams.correlationId];
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = nil;
    
    if(cacheItem.sessionKey)
    {
        NSString* jwtToken = [self createAccessTokenRequestJWTUsingRT:cacheItem];
        request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                        _requestParams.redirectUri, @"redirect_uri",
                        _requestParams.clientId, @"client_id",
                        @"2.0", @"windows_api_version",
                        @"urn:ietf:params:oauth:grant-type:jwt-bearer", OAUTH2_GRANT_TYPE,
                        jwtToken, @"request",
                        nil];
        
    }
    else
    {
        request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                        OAUTH2_REFRESH_TOKEN, OAUTH2_GRANT_TYPE,
                        refreshToken, OAUTH2_REFRESH_TOKEN,
                        [_requestParams clientId], OAUTH2_CLIENT_ID,
                        nil];
    }
    
    if (![NSString adIsStringNilOrBlank:[_requestParams resource]])
    {
        [request_data setObject:[_requestParams resource] forKey:OAUTH2_RESOURCE];
    }
    
    NSString* urlString = [_requestParams.tokenEndpoint stringByAppendingString:OIDC_OAUTH2_TOKEN_SUFFIX];
    
    NSLog(@"url: %@", urlString);
    
    OIDCWebAuthRequest* webReq =
    [[OIDCWebAuthRequest alloc] initWithURL:[NSURL URLWithString:urlString]
                                    context:_requestParams];
    [webReq setRequestDictionary:request_data];
    OIDC_LOG_INFO_F(@"Attempting to acquire an access token from refresh token", nil, @"clientId: '%@'; resource: '%@';", [_requestParams clientId], [_requestParams resource]);
    [webReq sendRequest:^(OIDCAuthenticationError *error, NSDictionary *response)
     {
         if (error)
         {
             completionBlock([OIDCAuthenticationResult resultFromError:error]);
             [webReq invalidate];
             return;
         }
         
         OIDCTokenCacheItem* resultItem = (cacheItem) ? cacheItem : [OIDCTokenCacheItem new];
         
         //Always ensure that the cache item has all of these set, especially in the broad token case, where the passed item
         //may have empty "resource" property:
         resultItem.resource = [_requestParams resource];
         resultItem.clientId = [_requestParams clientId];
         resultItem.authority = [_requestParams authority];
         
         
         OIDCAuthenticationResult *result = [resultItem processTokenResponse:response fromRefresh:YES requestCorrelationId:_requestParams.correlationId];
         if (cacheItem)//The request came from the cache item, update it:
         {
             [[_requestParams tokenCache] updateCacheToResult:result
                                                    cacheItem:resultItem
                                                 refreshToken:refreshToken
                                                      context:_requestParams];
         }
         result = [OIDCAuthenticationContext updateResult:result toUser:[_requestParams identifier]];//Verify the user (just in case)
         
         completionBlock(result);
         
         [webReq invalidate];
     }];
}

- (NSString*)createAccessTokenRequestJWTUsingRT:(OIDCTokenCacheItem*)cacheItem
{
    NSString* grantType = @"refresh_token";
    
    NSString* ctx = [[[NSUUID UUID] UUIDString] adComputeSHA256];
    NSDictionary *header = @{
                             @"alg" : @"HS256",
                             @"typ" : @"JWT",
                             @"ctx" : [OIDCHelpers convertBase64UrlStringToBase64NSString:[ctx adBase64UrlEncode]]
                             };
    
    NSInteger iat = round([[NSDate date] timeIntervalSince1970]);
    NSDictionary *payload = @{
                              @"resource" : [_requestParams resource],
                              @"client_id" : [_requestParams clientId],
                              @"refresh_token" : cacheItem.refreshToken,
                              @"iat" : [NSNumber numberWithInteger:iat],
                              @"nbf" : [NSNumber numberWithInteger:iat],
                              @"exp" : [NSNumber numberWithInteger:iat],
                              @"scope" : @"openid",
                              @"grant_type" : grantType,
                              @"aud" : [_requestParams authority]
                              };
    
    NSString* returnValue = [OIDCHelpers createSignedJWTUsingKeyDerivation:header
                                                                 payload:payload
                                                                 context:ctx
                                                            symmetricKey:cacheItem.sessionKey];
    return returnValue;
}

- (void)acquireTokenWithItem:(OIDCTokenCacheItem *)item
                 refreshType:(NSString *)refreshType
             completionBlock:(OIDCAuthenticationCallback)completionBlock
                    fallback:(OIDCAuthenticationCallback)fallback
{
    [[OIDCTelemetry sharedInstance] startEvent:[_requestParams telemetryRequestId] eventName:OIDC_TELEMETRY_EVENT_TOKEN_GRANT];
    [self acquireTokenByRefreshToken:item.refreshToken
                           cacheItem:item
                     completionBlock:^(OIDCAuthenticationResult *result)
     {
         OIDCTelemetryAPIEvent* event = [[OIDCTelemetryAPIEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_TOKEN_GRANT
                                                                        context:_requestParams];
         [event setGrantType:OIDC_TELEMETRY_VALUE_BY_REFRESH_TOKEN];
         [event setResultStatus:[result status]];
         [[OIDCTelemetry sharedInstance] stopEvent:[_requestParams telemetryRequestId] event:event];

         NSString* resultStatus = @"Succeded";
         
         if (result.status == OIDC_FAILED)
         {
             if (result.error.protocolCode)
             {
                 resultStatus = [NSString stringWithFormat:@"Failed (%@)", result.error.protocolCode];
             }
             else
             {
                 resultStatus = [NSString stringWithFormat:@"Failed (%@ %ld)", result.error.domain, (long)result.error.code];
             }
         }
         
         NSString* msg = nil;
         if (refreshType)
         {
             msg = [NSString stringWithFormat:@"Acquire Token with %@ Refresh Token %@.", refreshType, resultStatus];
         }
         else
         {
             msg = [NSString stringWithFormat:@"Acquire Token with Refresh Token %@.", resultStatus];
         }
         
         OIDC_LOG_INFO_F(msg, [_requestParams correlationId], @"clientId: '%@'; resource: '%@';", [_requestParams clientId], [_requestParams resource]);
         
         if ([OIDCAuthenticationContext isFinalResult:result])
         {
             completionBlock(result);
             return;
         }
         
         fallback(result);
     }];
}

/*
 This is the beginning of the cache look up sequence. We start by trying to find an access token that is not
 expired. If there's a single-resource-refresh-token it will be cached along side an expire AT, and we'll
 attempt to use that. If not we fall into the MRRT<-->FRT code.
 */

- (void)getAccessToken:(OIDCAuthenticationCallback)completionBlock
{
    //All of these should be set before calling this method:
    THROW_ON_NIL_ARGUMENT(completionBlock);
    NSUUID* correlationId = [_requestParams correlationId];
    
    OIDCAuthenticationError* error = nil;
    OIDCTokenCacheItem* item = [[_requestParams tokenCache] getATRTItemForUser:[_requestParams identifier]
                                                                    resource:[_requestParams resource]
                                                                    clientId:[_requestParams clientId]
                                                                     context:_requestParams
                                                                       error:&error];
    // If some error ocurred during the cache lookup then we need to fail out right away.
    if (!item && error)
    {
        completionBlock([OIDCAuthenticationResult resultFromError:error correlationId:correlationId]);
        return;
    }
    
    // If we didn't find an item at all there's a chance that we might be dealing with an "OAUTH" user
    // and we need to check the unknown user OAUTH token as well
    if (!item)
    {
        item = [[_requestParams tokenCache] getOAUTHUserTokenForResource:[_requestParams resource]
                                                               clientId:[_requestParams clientId]
                                                                context:_requestParams
                                                                  error:&error];
        if (!item && error)
        {
            completionBlock([OIDCAuthenticationResult resultFromError:error correlationId:correlationId]);
            return;
        }
        
        // If we still don't have anything from the cache to use then we should try to see if we have an MRRT
        // that matches.
        if (!item)
        {
            [self tryMRRT:completionBlock];
            return;
        }
    }
    
    // If we have a good (non-expired) access token then return it right away
    if (item.accessToken && !item.isExpired)
    {
        [OIDCLogger logToken:item.accessToken
                 tokenType:@"AT"
                 expiresOn:item.expiresOn
                   context:@"Returning"
             correlationId:_requestParams.correlationId];
        OIDCAuthenticationResult* result =
        [OIDCAuthenticationResult resultFromTokenCacheItem:item
                               multiResourceRefreshToken:NO
                                           correlationId:correlationId];
        completionBlock(result);
        return;
    }
    
    // If the access token is good in terms of extended lifetime then store it for later use
    if (item.accessToken && item.isExtendedLifetimeValid)
    {
        _extendedLifetimeAccessTokenItem = item;
    }
    
    [self tryRT:item completionBlock:completionBlock];
}

- (void)tryRT:(OIDCTokenCacheItem*)item completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    OIDCAuthenticationError* error = nil;
    
    if (!item.refreshToken)
    {
        // There's nothing usable in this cache item if extended lifetime also expires, delete it.
        if (!item.isExtendedLifetimeValid && ![[_requestParams tokenCache].dataSource removeItem:item error:&error] && error)
        {
            // If we failed to remove the item with an error, then return that error right away
            completionBlock([OIDCAuthenticationResult resultFromError:error correlationId:[_requestParams correlationId]]);
            return;
        }
        
        if (!item.userInformation.userId)
        {
            // If we don't have any userInformation in this token that means it came from an authority
            // that doesn't support MRRTs or FRTs either, so fail right now.
            completionBlock(nil);
            return;
        }
        [self tryMRRT:completionBlock];
        return;
    }
    
    [self acquireTokenWithItem:item
                   refreshType:nil
               completionBlock:completionBlock
                      fallback:^(OIDCAuthenticationResult* result)
     {
         // If we had an individual RT associated with this item then we aren't
         // talking to OIDC so there won't be an MRRT. End the silent flow immediately.
         completionBlock(result);
     }];
}

/*
 This method will try to find and use an MRRT, that matches the parameters of the authentication request.
 If it finds one marked with a family ID it will call tryFRT before attempting to use the MRRT.
 */
- (void)tryMRRT:(OIDCAuthenticationCallback)completionBlock
{
    OIDCAuthenticationError* error = nil;
    
    // If we don't have an item yet see if we can pull one out of the cache
    if (!_mrrtItem)
    {
        _mrrtItem = [[_requestParams tokenCache] getMRRTItemForUser:[_requestParams identifier]
                                                           clientId:[_requestParams clientId]
                                                            context:_requestParams
                                                              error:&error];
        if (!_mrrtItem && error)
        {
            completionBlock([OIDCAuthenticationResult resultFromError:error correlationId:[_requestParams correlationId]]);
            return;
        }
    }
    
    // If we still don't have an item try to use a FRT
    if (!_mrrtItem)
    {
        [self tryFRT:nil completionBlock:completionBlock];
        return;
    }
    
    // If our MRRT is marked with an Family ID and we haven't tried a FRT yet
    // try that first
    if (_mrrtItem.familyId && !_attemptedFRT)
    {
        [self tryFRT:_mrrtItem.familyId completionBlock:completionBlock];
        return;
    }
    
    // Otherwise try the MRRT
    [self acquireTokenWithItem:_mrrtItem
                   refreshType:@"Multi Resource"
               completionBlock:completionBlock
                      fallback:^(OIDCAuthenticationResult* result)
     {
         NSString* familyId = _mrrtItem.familyId;
         
         // Clear out the MRRT as it's not good anymore anyways
         _mrrtItem = nil;
         _mrrtResult = result;
         
         // Try the FRT in case it's there.
         [self tryFRT:familyId completionBlock:completionBlock];
     }];
}

/*
 This method will attempt to find and use a FRT matching the given family ID and the parameters of the
 authentication request, if we've not already tried an FRT during this request. If it fails it will call
 -tryMRRT: If we have already tried to use an FRT then we go to interactive auth.
 */

- (void)tryFRT:(NSString*)familyId completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    if (_attemptedFRT)
    {
        completionBlock(_mrrtResult);
        return;
    }
    _attemptedFRT = YES;
    
    OIDCAuthenticationError* error = nil;
    OIDCTokenCacheItem* frtItem = [[_requestParams tokenCache] getFRTItemForUser:[_requestParams identifier]
                                                                      familyId:familyId
                                                                       context:_requestParams
                                                                         error:&error];
    if (!frtItem && error)
    {
        completionBlock([OIDCAuthenticationResult resultFromError:error correlationId:[_requestParams correlationId]]);
        return;
    }
    
    if (!frtItem)
    {
        if (_mrrtItem)
        {
            // If we still have an MRRT item retrieved in this request then attempt to use that.
            [self tryMRRT:completionBlock];
        }
        else
        {
            // Otherwise go to interactive auth
            completionBlock(_mrrtResult);
        }
        return;
    }
    
    [self acquireTokenWithItem:frtItem refreshType:@"Family" completionBlock:completionBlock fallback:^(OIDCAuthenticationResult *result)
     {
         (void)result;
         
         if (_mrrtItem)
         {
             // If we still have an MRRT item retrieved in this request then attempt to use that.
             [self tryMRRT:completionBlock];
             return;
         }
         
         completionBlock(_mrrtResult);
     }];
}

- (BOOL) isServerUnavailable:(OIDCAuthenticationResult *)result
{
    if (![[result.error domain] isEqualToString:OIDCHTTPErrorCodeDomain])
    {
        return NO;
    }
    
    return ([result.error code] >= 500 && [result.error code] <= 599);
}

@end
