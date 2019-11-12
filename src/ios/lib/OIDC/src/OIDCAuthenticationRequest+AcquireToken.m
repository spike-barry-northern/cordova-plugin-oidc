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

#import "OIDCAuthenticationRequest.h"
#import "OIDCAuthenticationContext+Internal.h"
#import "OIDCTokenCacheItem+Internal.h"
#import "OIDCAuthorityValidation.h"
#import "OIDCHelpers.h"
#import "OIDCUserIdentifier.h"
#import "OIDCTokenCacheKey.h"
#import "OIDCAcquireTokenSilentHandler.h"
#import "OIDCTelemetry.h"
#import "OIDCTelemetry+Internal.h"
#import "OIDCTelemetryAPIEvent.h"
#import "OIDCTelemetryBrokerEvent.h"
#import "OIDCTelemetryEventStrings.h"
#import "OIDCBrokerHelper.h"
#import "NSDictionary+OIDCExtensions.h"

@implementation OIDCAuthenticationRequest (AcquireToken)

#pragma mark -
#pragma mark AcquireToken

- (void)acquireToken:(NSString *)apiId
     completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    [[OIDCTelemetry sharedInstance] startEvent:self.telemetryRequestId
                                   eventName:OIDC_TELEMETRY_EVENT_API_EVENT];
    
    OIDC_REQUEST_CHECK_ARGUMENT([_requestParams resource]);
    [self ensureRequest];
    NSString* telemetryRequestId = [_requestParams telemetryRequestId];
    
    __block NSString* log = [NSString stringWithFormat:@"##### BEGIN acquireToken%@ (authority = %@, resource = %@, clientId = %@, idtype = %@) #####",
                             _silent ? @"Silent" : @"", _requestParams.authority, _requestParams.resource, _requestParams.clientId, [_requestParams.identifier typeAsString]];
    OIDC_LOG_INFO_F(log, _requestParams.correlationId, @"userId = %@", _requestParams.identifier.userId);
    
    OIDCAuthenticationCallback wrappedCallback = ^void(OIDCAuthenticationResult* result)
    {
        NSString* finalLog = nil;
        if (result.status == OIDC_SUCCEEDED)
        {
            finalLog = [NSString stringWithFormat:@"##### END %@ succeeded. #####", log];
        }
        else
        {
            OIDCAuthenticationError* error = result.error;
            finalLog = [NSString stringWithFormat:@"##### END %@ failed { domain: %@ code: %ld protocolCode: %@ errorDetails: %@} #####",
                        log, error.domain, (long)error.code, error.protocolCode, error.errorDetails];
        }
        
        
        OIDC_LOG_INFO(finalLog, result.correlationId, nil);
        
        OIDCTelemetryAPIEvent* event = [[OIDCTelemetryAPIEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_API_EVENT
                                                                       context:self];
        [event setApiId:apiId];
        
        [event setCorrelationId:self.correlationId];
        [event setClientId:_requestParams.clientId];
        [event setAuthority:_context.authority];
        [event setExtendedExpiresOnSetting:[_requestParams extendedLifetime]? OIDC_TELEMETRY_VALUE_YES:OIDC_TELEMETRY_VALUE_NO];
        [event setPromptBehavior:_promptBehavior];
        if ([result tokenCacheItem])
        {
            [event setUserInformation:result.tokenCacheItem.userInformation];
        }
        else
        {
            [event setUserId:_requestParams.identifier.userId];
        }
        [event setResultStatus:result.status];
        [event setIsExtendedLifeTimeToken:[result extendedLifeTimeToken]? OIDC_TELEMETRY_VALUE_YES:OIDC_TELEMETRY_VALUE_NO];
        [event setErrorCode:[result.error code]];
        [event setErrorDomain:[result.error domain]];
        [event setProtocolCode:[[result error] protocolCode]];
        
        [[OIDCTelemetry sharedInstance] stopEvent:self.telemetryRequestId event:event];
        //flush all events in the end of the acquireToken call
        [[OIDCTelemetry sharedInstance] flush:self.telemetryRequestId];
        
        completionBlock(result);
    };
    
    if (_samlAssertion == nil && !_silent && ![NSThread isMainThread])
    {
        OIDCAuthenticationError* error =
        [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_UI_NOT_ON_MAIN_THREOIDC
                                               protocolCode:nil
                                               errorDetails:@"Interactive authentication requests must originate from the main thread"
                                              correlationId:_requestParams.correlationId];
        
        wrappedCallback([OIDCAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
        return;
    }
    
    if (![self checkExtraQueryParameters])
    {
        OIDCAuthenticationError* error =
        [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_DEVELOPER_INVALID_ARGUMENT
                                               protocolCode:nil
                                               errorDetails:@"extraQueryParameters is not properly encoded. Please make sure it is URL encoded."
                                              correlationId:_requestParams.correlationId];
        wrappedCallback([OIDCAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
        return;
    }
    
    OIDCAuthenticationError *error = nil;
    if (![self checkClaims:&error])
    {
        wrappedCallback([OIDCAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
        return;
    }
    
    if (!_silent && _context.credentialsType == OIDC_CREDENTIALS_AUTO && ![OIDCAuthenticationRequest validBrokerRedirectUri:_requestParams.redirectUri])
    {
        OIDCAuthenticationError* error =
        [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_TOKENBROKER_INVALID_REDIRECT_URI
                                               protocolCode:nil
                                               errorDetails:OIDCRedirectUriInvalidError
                                              correlationId:_requestParams.correlationId];
        wrappedCallback([OIDCAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
        return;
    }
    
    [[OIDCTelemetry sharedInstance] startEvent:telemetryRequestId eventName:OIDC_TELEMETRY_EVENT_AUTHORITY_VALIDATION];
    
    OIDCAuthorityValidation* authorityValidation = [OIDCAuthorityValidation sharedInstance];
    [authorityValidation checkAuthority:_requestParams
                      validateAuthority:_context.validateAuthority
                        completionBlock:^(BOOL validated, OIDCAuthenticationError *error)
     {
         OIDCTelemetryAPIEvent* event = [[OIDCTelemetryAPIEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_AUTHORITY_VALIDATION
                                                                        context:_requestParams];
         [event setAuthorityValidationStatus:validated ? OIDC_TELEMETRY_VALUE_YES:OIDC_TELEMETRY_VALUE_NO];
         [event setAuthority:_context.authority];
         [[OIDCTelemetry sharedInstance] stopEvent:telemetryRequestId event:event];
         
         if (error)
         {
             wrappedCallback([OIDCAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
         }
         else
         {
             [self validatedAcquireToken:wrappedCallback];
         }
     }];    
}

- (BOOL)checkExtraQueryParameters
{
    if ([NSString adIsStringNilOrBlank:_queryParams])
    {
        return YES;
    }
    
    NSString* queryParams = _queryParams.adTrimmedString;
    if ([queryParams hasPrefix:@"&"])
    {
        queryParams = [queryParams substringFromIndex:1];
    }
    NSURL* url = [NSURL URLWithString:[NSMutableString stringWithFormat:@"%@?%@", _context.authority, queryParams]];
    
    return url!=nil;
}

- (BOOL)checkClaims:(OIDCAuthenticationError *__autoreleasing *)error
{
    if ([NSString adIsStringNilOrBlank:_claims])
    {
        return YES;
    }
    
    // Make sure claims is not in EQP
    NSDictionary *queryParamsDict = [NSDictionary adURLFormDecode:_queryParams];
    if (queryParamsDict[@"claims"])
    {
        if (error)
        {
            *error = [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_DEVELOPER_INVALID_ARGUMENT
                                                            protocolCode:nil
                                                            errorDetails:@"Duplicate claims parameter is found in extraQueryParameters. Please remove it."
                                                           correlationId:_requestParams.correlationId];
        }
        return NO;
    }
    
    // Make sure claims is properly encoded
    NSString* claimsParams = _claims.adTrimmedString;
    NSURL* url = [NSURL URLWithString:[NSMutableString stringWithFormat:@"%@?claims=%@", _context.authority, claimsParams]];
    if (!url)
    {
        if (error)
        {
            *error = [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_DEVELOPER_INVALID_ARGUMENT
                                                            protocolCode:nil
                                                            errorDetails:@"claims is not properly encoded. Please make sure it is URL encoded."
                                                           correlationId:_requestParams.correlationId];
        }
        return NO;
    }
    
    // Always skip cache if claims parameter is not nil/empty
    _skipCache = YES;
    
    return YES;
}

- (void)validatedAcquireToken:(OIDCAuthenticationCallback)completionBlock
{
    [self ensureRequest];
    
    if (![OIDCAuthenticationContext isForcedAuthorization:_promptBehavior] && !_skipCache && [_context hasCacheStore])
    {
        [[OIDCTelemetry sharedInstance] startEvent:[self telemetryRequestId] eventName:OIDC_TELEMETRY_EVENT_ACQUIRE_TOKEN_SILENT];
        OIDCAcquireTokenSilentHandler* request = [OIDCAcquireTokenSilentHandler requestWithParams:_requestParams];
        [request getToken:^(OIDCAuthenticationResult *result)
        {
            OIDCTelemetryAPIEvent* event = [[OIDCTelemetryAPIEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_ACQUIRE_TOKEN_SILENT
                                                                           context:_requestParams];
            [[OIDCTelemetry sharedInstance] stopEvent:[self telemetryRequestId] event:event];
            if ([OIDCAuthenticationContext isFinalResult:result])
            {
                completionBlock(result);
                return;
            }
            
            _underlyingError = result.error;
            
            [self requestToken:completionBlock];
        }];
        return;
    }
    
    [self requestToken:completionBlock];
}

- (void)requestToken:(OIDCAuthenticationCallback)completionBlock
{
    [self ensureRequest];
    NSUUID* correlationId = [_requestParams correlationId];
    
    if (_samlAssertion)
    {
        [self requestTokenByAssertion:^(OIDCAuthenticationResult *result){
            if (OIDC_SUCCEEDED == result.status)
            {
                [[_requestParams tokenCache] updateCacheToResult:result
                                                       cacheItem:nil
                                                    refreshToken:nil
                                                         context:_requestParams];
                result = [OIDCAuthenticationContext updateResult:result toUser:[_requestParams identifier]];
            }
            completionBlock(result);
        }];
        return;
    }

    if (_silent && !_allowSilent)
    {
        //The cache lookup and refresh token attempt have been unsuccessful,
        //so credentials are needed to get an access token, but the developer, requested
        //no UI to be shown:
        NSDictionary* underlyingError = _underlyingError ? @{NSUnderlyingErrorKey:_underlyingError} : nil;
        OIDCAuthenticationError* error =
        [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_SERVER_USER_INPUT_NEEDED
                                               protocolCode:nil
                                               errorDetails:OIDCCredentialsNeeded
                                                   userInfo:underlyingError
                                              correlationId:correlationId];
        
        OIDCAuthenticationResult* result = [OIDCAuthenticationResult resultFromError:error correlationId:correlationId];
        completionBlock(result);
        return;
    }
    
    //can't pop UI or go to broker in an extension
    if ([[[NSBundle mainBundle] bundlePath] hasSuffix:@".appex"])
    {
        // This is an app extension. Return an error unless a webview is specified by the
        // extension and embedded auth is being used.
        BOOL isEmbeddedWebView = (nil != _context.webView) && (OIDC_CREDENTIALS_EMBEDDED == _context.credentialsType);
        if (!isEmbeddedWebView)
        {
            OIDCAuthenticationError* error =
            [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION
                                                   protocolCode:nil
                                                   errorDetails:OIDCInteractionNotSupportedInExtension
                                                  correlationId:correlationId];
            OIDCAuthenticationResult* result = [OIDCAuthenticationResult resultFromError:error correlationId:correlationId];
            completionBlock(result);
            return;
        }
    }
    
    [self requestTokenImpl:completionBlock];
}

- (void)requestTokenImpl:(OIDCAuthenticationCallback)completionBlock
{
#if TARGET_OS_IPHONE
    //call the broker.
    if ([self canUseBroker])
    {
        
#if !OIDC_BROKER
        if (![self takeExclusionLock:completionBlock])
        {
            return;
        }
#endif
        
        OIDCAuthenticationError* error = nil;
        NSURL* brokerURL = [self composeBrokerRequest:&error];
        if (!brokerURL)
        {
            completionBlock([OIDCAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
            return;
        }
        
        [[OIDCTelemetry sharedInstance] startEvent:[self telemetryRequestId] eventName:OIDC_TELEMETRY_EVENT_LAUNCH_BROKER];
        [OIDCBrokerHelper invokeBroker:brokerURL completionHandler:^(OIDCAuthenticationResult* result)
         {
             OIDCTelemetryBrokerEvent* event = [[OIDCTelemetryBrokerEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_LAUNCH_BROKER
                                                                                requestId:_requestParams.telemetryRequestId
                                                                            correlationId:_requestParams.correlationId];
             [event setResultStatus:[result status]];
             [event setBrokerAppVersion:s_oidcBrokerAppVersion];
             [event setBrokerProtocolVersion:s_oidcBrokerProtocolVersion];
             [[OIDCTelemetry sharedInstance] stopEvent:[self telemetryRequestId] event:event];

#if !OIDC_BROKER
             [OIDCAuthenticationRequest releaseExclusionLock];
#endif

             completionBlock(result);
         }];
        return;
    }
#endif

    if (![self takeExclusionLock:completionBlock])
    {
        return;
    }

    // Always release the exclusion lock on completion
    OIDCAuthenticationCallback originalCompletionBlock = completionBlock;
    completionBlock = ^(OIDCAuthenticationResult* result)
    {
        [OIDCAuthenticationRequest releaseExclusionLock];
        originalCompletionBlock(result);
    };

    __block BOOL silentRequest = _allowSilent;
    
    NSString* telemetryRequestId = [_requestParams telemetryRequestId];
    
    // Get the code first:
    [[OIDCTelemetry sharedInstance] startEvent:telemetryRequestId eventName:OIDC_TELEMETRY_EVENT_AUTHORIZATION_CODE];
    [self requestCode:^(NSString * code, OIDCAuthenticationError *error)
     {
         OIDCTelemetryAPIEvent* event = [[OIDCTelemetryAPIEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_AUTHORIZATION_CODE
                                                                        context:_requestParams];

         if (error)
         {
             if (silentRequest)
             {
                 _allowSilent = NO;
                 [self requestToken:completionBlock];
                 return;
             }
             
             OIDCAuthenticationResult* result = (OIDC_ERROR_UI_USER_CANCEL == error.code) ? [OIDCAuthenticationResult resultFromCancellation:_requestParams.correlationId]
             : [OIDCAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId];
             [event setAPIStatus:(OIDC_ERROR_UI_USER_CANCEL == error.code) ? OIDC_TELEMETRY_VALUE_CANCELLED:OIDC_TELEMETRY_VALUE_FAILED];
             [[OIDCTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:event];
             completionBlock(result);
         }
         else
         {
#if TARGET_OS_IPHONE
             if([code hasPrefix:@"oidcauth://"])
             {
                 [event setAPIStatus:@"try to prompt to install broker"];
                 [[OIDCTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:event];
                 
                 OIDCAuthenticationError* error = nil;
                 NSURL* brokerRequestURL = [self composeBrokerRequest:&error];
                 if (!brokerRequestURL)
                 {
                     completionBlock([OIDCAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
                     return;
                 }
                 
                 [OIDCBrokerHelper promptBrokerInstall:[NSURL URLWithString:code]
                                       brokerRequest:brokerRequestURL
                                   completionHandler:completionBlock];
                 return;
             }
             else
#endif
             {
                 [event setAPIStatus:OIDC_TELEMETRY_VALUE_SUCCEEDED];
                 [[OIDCTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:event];
                 
                 
                
                 if (![NSString adIsStringNilOrBlank:code])
                 {
                     //[_requestParams authority]
                     OIDCTokenCacheItem *cacheItem = [[_requestParams tokenCache] updateCacheToCode:code type:@"id_token" refreshToken:nil context:_requestParams];
                     
                     OIDCAuthenticationResult *result = [OIDCAuthenticationResult resultFromTokenCacheItem:cacheItem multiResourceRefreshToken:false correlationId:[_requestParams correlationId]];
                     completionBlock(result);
                 }
                 else {
                     completionBlock(nil);
                 }                
                 
             }
         }
     }];
}

// Generic OAuth2 Authorization Request, obtains a token from an authorization code.
- (void)requestTokenByCode:(NSString *)code
           completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    HANDLE_ARGUMENT(code, [_requestParams correlationId]);
    [self ensureRequest];
    OIDC_LOG_VERBOSE_F(@"Requesting token from authorization code.", [_requestParams correlationId], @"Requesting token by authorization code for resource: %@", [_requestParams resource]);
    
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                         OAUTH2_AUTHORIZATION_CODE, OAUTH2_GRANT_TYPE,
                                         code, OAUTH2_CODE,
                                         [_requestParams clientId], OAUTH2_CLIENT_ID,
                                         [_requestParams redirectUri], OAUTH2_REDIRECT_URI,
                                         nil];
    if (![NSString adIsStringNilOrBlank:_scope])
    {
        [request_data setValue:_scope forKey:OAUTH2_SCOPE];
    }
    
    [self executeRequest:request_data
              completion:completionBlock];
}

@end
