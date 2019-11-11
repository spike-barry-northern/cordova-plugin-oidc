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

#import "NSDictionary+OIDCExtensions.h"
#import "NSString+OIDCHelperMethods.h"

#import "OIDCAuthenticationContext+Internal.h"
#import "OIDCAuthenticationRequest.h"
#import "OIDCAuthenticationSettings.h"
#import "OIDCBrokerHelper.h"
#import "OIDCHelpers.h"
#import "OIDCPkeyAuthHelper.h"
#import "OIDCTokenCacheItem+Internal.h"
#import "OIDCUserIdentifier.h"
#import "OIDCUserInformation.h"
#import "OIDCWebAuthController+Internal.h"
#import "OIDCAuthenticationResult.h"
#import "OIDCTelemetry.h"
#import "OIDCTelemetry+Internal.h"
#import "OIDCTelemetryBrokerEvent.h"

#import "OIDCOAuth2Constants.h"

#if TARGET_OS_IPHONE
#import "OIDCKeychainTokenCache+Internal.h"
#import "OIDCBrokerKeyHelper.h"
#import "OIDCBrokerNotificationManager.h"
#import "OIDCKeychainUtil.h"
#endif // TARGET_OS_IPHONE

NSString* s_oidcBrokerAppVersion = nil;
NSString* s_oidcBrokerProtocolVersion = nil;

NSString* kOidcResumeDictionaryKey = @"oidc-broker-resume-dictionary";

@implementation OIDCAuthenticationRequest (Broker)

+ (BOOL)validBrokerRedirectUri:(NSString*)url
{
    (void)s_oidcBrokerAppVersion;
    (void)s_oidcBrokerProtocolVersion;
    
#if OIDC_BROKER
    // Allow the broker app to use a special redirect URI when acquiring tokens
    if ([url isEqualToString:OIDC_BROKER_APP_REDIRECT_URI])
    {
        return YES;
    }
#endif
    
    NSArray* urlTypes = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleURLTypes"];
    
    NSURL* redirectURI = [NSURL URLWithString:url];
    
    NSString* scheme = redirectURI.scheme;
    if (!scheme)
    {
        return NO;
    }
    
    NSString* bundleId = [[NSBundle mainBundle] bundleIdentifier];
    NSString* host = [redirectURI host];
    if (![host isEqualToString:bundleId])
    {
        return NO;
    }
    
    for (NSDictionary* urlRole in urlTypes)
    {
        NSArray* urlSchemes = [urlRole objectForKey:@"CFBundleURLSchemes"];
        if ([urlSchemes containsObject:scheme])
        {
            return YES;
        }
    }
    
    return NO;
}

/*!
    Process the broker response and call the completion block, if it is available.
 
    @return YES if the URL was a properly decoded broker response
 */
+ (BOOL)internalHandleBrokerResponse:(NSURL *)response
{
#if TARGET_OS_IPHONE
    __block OIDCAuthenticationCallback completionBlock = [OIDCBrokerHelper copyAndClearCompletionBlock];
    
    OIDCAuthenticationError* error = nil;
    OIDCAuthenticationResult* result = [self processBrokerResponse:response
                                                           error:&error];
    BOOL fReturn = YES;
    
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kOidcResumeDictionaryKey];
    if (!result)
    {
        result = [OIDCAuthenticationResult resultFromError:error];
        fReturn = NO;
    }
    
    [[NSNotificationCenter defaultCenter] postNotificationName:OIDCWebAuthDidReceieveResponseFromBroker
                                                        object:nil
                                                      userInfo:@{ @"response" : result }];
    
    // Regardless of whether or not processing the broker response succeeded we always have to call
    // the completion block.
    if (completionBlock)
    {
        completionBlock(result);
    }
    else if (fReturn)
    {
        OIDC_LOG_ERROR(@"Received broker response without a completionBlock.", OIDC_FAILED, nil, nil);
        
        [OIDCWebAuthController setInterruptedBrokerResult:result];
    }
    
    return fReturn;
#else
    (void)response;
    return NO;
#endif // TARGET_OS_IPHONE
}

/*!
    Processes the broker response from the URL
 
    @param  response    The URL the application received from the openURL: handler
    @param  error       (Optional) Any error that occurred trying to process the broker response (note: errors
                        sent in the response itself will be returned as a result, and not populate this parameter)

    @return The result contained in the broker response, nil if the URL could not be processed
 */
+ (OIDCAuthenticationResult *)processBrokerResponse:(NSURL *)response
                                            error:(OIDCAuthenticationError * __autoreleasing *)error
{
#if TARGET_OS_IPHONE

    if (!response)
    {
        
        return nil;
    }
    
    NSDictionary* resumeDictionary = [[NSUserDefaults standardUserDefaults] objectForKey:kOidcResumeDictionaryKey];
    if (!resumeDictionary)
    {
        AUTH_ERROR(OIDC_ERROR_TOKENBROKER_NO_RESUME_STATE, @"No resume state found in NSUserDefaults", nil);
        return nil;
    }
    
    NSUUID* correlationId = [[NSUUID alloc] initWithUUIDString:[resumeDictionary objectForKey:@"correlation_id"]];
    NSString* redirectUri = [resumeDictionary objectForKey:@"redirect_uri"];
    if (!redirectUri)
    {
        AUTH_ERROR(OIDC_ERROR_TOKENBROKER_BOIDC_RESUME_STATE, @"Resume state is missing the redirect uri!", correlationId);
        return nil;
    }
    
    // Check to make sure this response is coming from the redirect URI we're expecting.
    if (![[[response absoluteString] lowercaseString] hasPrefix:[redirectUri lowercaseString]])
    {
        AUTH_ERROR(OIDC_ERROR_TOKENBROKER_MISMATCHED_RESUME_STATE, @"URL not coming from the expected redirect URI!", correlationId);
        return nil;
    }
    
    // NSURLComponents resolves some URLs which can't get resolved by NSURL
    NSURLComponents* components = [NSURLComponents componentsWithURL:response resolvingAgainstBaseURL:NO];
    NSString *qp = [components percentEncodedQuery];
    //expect to either response or error and description, AND correlation_id AND hash.
    NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
    
    if([queryParamsMap valueForKey:OAUTH2_ERROR_DESCRIPTION])
    {
        return [OIDCAuthenticationResult resultFromBrokerResponse:queryParamsMap];
    }
    
    // Encrypting the broker response should not be a requirement on Mac as there shouldn't be a possibility of the response
    // accidentally going to the wrong app
    NSString* hash = [queryParamsMap valueForKey:BROKER_HASH_KEY];
    if (!hash)
    {
        AUTH_ERROR(OIDC_ERROR_TOKENBROKER_HASH_MISSING, @"Key hash is missing from the broker response", correlationId);
        return nil;
    }
    
    NSString* encryptedBase64Response = [queryParamsMap valueForKey:BROKER_RESPONSE_KEY];
    NSString* msgVer = [queryParamsMap valueForKey:BROKER_MESSAGE_VERSION];
    NSInteger protocolVersion = 1;
    
    if (msgVer)
    {
        protocolVersion = [msgVer integerValue];
    }
    s_oidcBrokerProtocolVersion = msgVer;
    
    //decrypt response first
    OIDCBrokerKeyHelper* brokerHelper = [[OIDCBrokerKeyHelper alloc] init];
    OIDCAuthenticationError* decryptionError = nil;
    NSData *encryptedResponse = [NSString adBase64UrlDecodeData:encryptedBase64Response ];
    NSData* decrypted = [brokerHelper decryptBrokerResponse:encryptedResponse
                                                    version:protocolVersion
                                                      error:&decryptionError];
    if (!decrypted)
    {
        AUTH_ERROR_UNDERLYING(OIDC_ERROR_TOKENBROKER_DECRYPTION_FAILED, @"Failed to decrypt broker message", decryptionError, correlationId)
        return nil;
    }
    
    
    NSString* decryptedString = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
    //now compute the hash on the unencrypted data
    NSString* actualHash = [OIDCPkeyAuthHelper computeThumbprint:decrypted isSha2:YES];
    if(![hash isEqualToString:actualHash])
    {
        AUTH_ERROR(OIDC_ERROR_TOKENBROKER_RESPONSE_HASH_MISMATCH, @"Decrypted response does not match the hash", correlationId);
        return nil;
    }
    
    // create response from the decrypted payload
    queryParamsMap = [NSDictionary adURLFormDecode:decryptedString];
    [OIDCHelpers removeNullStringFrom:queryParamsMap];
    OIDCAuthenticationResult* result = [OIDCAuthenticationResult resultFromBrokerResponse:queryParamsMap];
    
    s_oidcBrokerAppVersion = [queryParamsMap valueForKey:BROKER_APP_VERSION];
    
    NSString* keychainGroup = resumeDictionary[@"keychain_group"];
    if (OIDC_SUCCEEDED == result.status && keychainGroup)
    {
        OIDCTokenCacheAccessor* cache = [[OIDCTokenCacheAccessor alloc] initWithDataSource:[OIDCKeychainTokenCache keychainCacheForGroup:keychainGroup]
                                                                             authority:result.tokenCacheItem.authority];
        
        [cache updateCacheToResult:result cacheItem:nil refreshToken:nil context:nil];
        
        NSString* userId = [[[result tokenCacheItem] userInformation] userId];
        [OIDCAuthenticationContext updateResult:result
                                       toUser:[OIDCUserIdentifier identifierWithId:userId]];
    }
    
    return result;
#else
    (void)response;
    AUTH_ERROR(OIDC_ERROR_UNEXPECTED, @"broker response parsing not supported on Mac", nil);
    return nil;
#endif
}

- (BOOL)canUseBroker
{
    return _context.credentialsType == OIDC_CREDENTIALS_AUTO && _context.validateAuthority == YES && [OIDCBrokerHelper canUseBroker] && ![OIDCHelpers isOAUTHInstance:_requestParams.authority];
}

- (NSURL *)composeBrokerRequest:(OIDCAuthenticationError* __autoreleasing *)error
{
    ARG_RETURN_IF_NIL(_requestParams.authority, _requestParams.correlationId);
    //ARG_RETURN_IF_NIL(_requestParams.resource, _requestParams.correlationId);
    ARG_RETURN_IF_NIL(_requestParams.clientId, _requestParams.correlationId);
    //ARG_RETURN_IF_NIL(_requestParams.correlationId, _requestParams.correlationId);
    
    if(![OIDCAuthenticationRequest validBrokerRedirectUri:_requestParams.redirectUri])
    {
        AUTH_ERROR(OIDC_ERROR_TOKENBROKER_INVALID_REDIRECT_URI, OIDCRedirectUriInvalidError, _requestParams.correlationId);
        return nil;
    }
    
    OIDC_LOG_INFO(@"Invoking broker for authentication", _requestParams.correlationId, nil);
#if TARGET_OS_IPHONE // Broker Message Encryption
    OIDCBrokerKeyHelper* brokerHelper = [[OIDCBrokerKeyHelper alloc] init];
    NSData* key = [brokerHelper getBrokerKey:error];
    AUTH_ERROR_RETURN_IF_NIL(key, OIDC_ERROR_UNEXPECTED, @"Unable to retrieve broker key.", _requestParams.correlationId);
    
    NSString* base64Key = [NSString adBase64UrlEncodeData:key];
    AUTH_ERROR_RETURN_IF_NIL(base64Key, OIDC_ERROR_UNEXPECTED, @"Unable to base64 encode broker key.", _requestParams.correlationId);
    NSString* base64UrlKey = [base64Key adUrlFormEncode];
    AUTH_ERROR_RETURN_IF_NIL(base64UrlKey, OIDC_ERROR_UNEXPECTED, @"Unable to URL encode broker key.", _requestParams.correlationId);
#endif // TARGET_OS_IPHONE Broker Message Encryption
    
    NSString* oidcVersion = [OIDCLogger getAdalVersion];
    AUTH_ERROR_RETURN_IF_NIL(oidcVersion, OIDC_ERROR_UNEXPECTED, @"Unable to retrieve OIDC version.", _requestParams.correlationId);
    
    NSDictionary* queryDictionary =
    @{
      //@"authority"      : _requestParams.authority,
      @"response_type"      : @"id_token",
      //@"resource"       : _requestParams.resource,
      @"client_id"      : _requestParams.clientId,
      @"redirect_uri"   : _requestParams.redirectUri,
      @"nonce"   : @"ff885571-6f66-432c-93b4-6463a563d080",

      //@"username_type"  : _requestParams.identifier ? [_requestParams.identifier typeAsString] : @"",
      //@"username"       : _requestParams.identifier.userId ? _requestParams.identifier.userId : @"",
      //@"force"          : _promptBehavior == OIDC_FORCE_PROMPT ? @"YES" : @"NO",
      //@"skip_cache"     : _skipCache ? @"YES" : @"NO",
      //@"correlation_id" : _requestParams.correlationId,
#if TARGET_OS_IPHONE // Broker Message Encryption
      @"broker_key"     : base64UrlKey,
#endif // TARGET_OS_IPHONE Broker Message Encryption
      //@"client_version" : oidcVersion,
      //BROKER_MAX_PROTOCOL_VERSION : @"2",
      @"extra_qp"       : _queryParams ? _queryParams : @"",
      //@"claims"         : _claims ? _claims : @"",
      };
    
    NSDictionary<NSString *, NSString *>* resumeDictionary = nil;
#if TARGET_OS_IPHONE
    id<OIDCTokenCacheDataSource> dataSource = [_requestParams.tokenCache dataSource];
    if (dataSource && [dataSource isKindOfClass:[OIDCKeychainTokenCache class]])
    {
        NSString* keychainGroup = [(OIDCKeychainTokenCache*)dataSource sharedGroup];
        NSString* teamId = [OIDCKeychainUtil keychainTeamId:error];
        if (!teamId)
        {
            return nil;
        }
        if (teamId && [keychainGroup hasPrefix:teamId])
        {
            keychainGroup = [keychainGroup substringFromIndex:teamId.length + 1];
        }
        resumeDictionary =
        @{
          @"authority"        : _requestParams.authority,
          @"resource"         : _requestParams.resource,
          @"client_id"        : _requestParams.clientId,
          @"redirect_uri"     : _requestParams.redirectUri,
          @"correlation_id"   : _requestParams.correlationId.UUIDString,
          @"keychain_group"   : keychainGroup
          };

    }
    else
#endif
    {
        resumeDictionary =
        @{
          @"authority"        : _requestParams.authority,
          @"resource"         : _requestParams.resource,
          @"client_id"        : _requestParams.clientId,
          @"redirect_uri"     : _requestParams.redirectUri,
          @"correlation_id"   : _requestParams.correlationId.UUIDString,
          };
    }
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kOidcResumeDictionaryKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    NSString* query = [queryDictionary adURLFormEncode];
    
    NSURL* brokerRequestURL = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://broker?%@", OIDC_BROKER_SCHEME, query]];
    AUTH_ERROR_RETURN_IF_NIL(brokerRequestURL, OIDC_ERROR_UNEXPECTED, @"Unable to encode broker request URL", _requestParams.correlationId);
    
    return brokerRequestURL;
}

@end
