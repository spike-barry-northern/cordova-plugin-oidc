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

#import "OIDCAuthenticationContext+Internal.h"
#import "OIDCWebRequest.h"
#import "OIDCWorkPlaceJoinConstants.h"
#import "NSDictionary+OIDCExtensions.h"
#import "OIDCClientMetrics.h"
#import "OIDCWebResponse.h"
#import "OIDCPkeyAuthHelper.h"
#import "OIDCAuthenticationSettings.h"
#import "OIDCWebAuthController.h"
#import "OIDCWebAuthController+Internal.h"
#import "OIDCHelpers.h"
#import "NSURL+OIDCExtensions.h"
#import "OIDCUserIdentifier.h"
#import "OIDCAuthenticationRequest.h"
#import "OIDCTokenCacheItem+Internal.h"
#import "OIDCWebAuthRequest.h"

#import <CommonCrypto/CommonCrypto.h>
#import <libkern/OSAtomic.h>

@implementation OIDCAuthenticationRequest (WebRequest)

- (void)executeRequest:(NSDictionary *)request_data
            completion:(OIDCAuthenticationCallback)completionBlock
{
    NSString* urlString = [_context.tokenEndpoint stringByAppendingString:OIDC_OAUTH2_TOKEN_SUFFIX];
    
    NSLog(@"url: %@", urlString);
    
    OIDCWebAuthRequest* req = [[OIDCWebAuthRequest alloc] initWithURL:[NSURL URLWithString:urlString]
                                                          context:_requestParams];
    [req setRequestDictionary:request_data];
    [req sendRequest:^(OIDCAuthenticationError *error, NSDictionary *response)
     {
         if (error)
         {
             completionBlock([OIDCAuthenticationResult resultFromError:error]);
             [req invalidate];
             return;
         }
         
         //Prefill the known elements in the item. These can be overridden by the response:
         OIDCTokenCacheItem* item = [OIDCTokenCacheItem new];
         item.resource = [_requestParams resource];
         item.clientId = [_requestParams clientId];
         item.authority = _context.authority;
         OIDCAuthenticationResult* result = [item processTokenResponse:response
                                                         fromRefresh:NO
                                                requestCorrelationId:[_requestParams correlationId]];
         completionBlock(result);
         
         [req invalidate];
     }];
}

// Ensures that the state comes back in the response:
- (BOOL)verifyStateFromDictionary: (NSDictionary*) dictionary
{
    NSDictionary *state = [NSDictionary adURLFormDecode:[[dictionary objectForKey:OAUTH2_STATE] adBase64UrlDecode]];
    if (state.count != 0)
    {
        NSString *authorizationServer = [state objectForKey:@"a"];
        NSString *resource            = [state objectForKey:@"r"];
        
        if (![NSString adIsStringNilOrBlank:authorizationServer] && ![NSString adIsStringNilOrBlank:resource])
        {
            OIDC_LOG_VERBOSE_F(@"State", [_requestParams correlationId], @"The authorization server returned the following state: %@", state);
            return YES;
        }
    }
    OIDC_LOG_WARN_F(@"State error", [_requestParams correlationId], @"Missing or invalid state returned: %@", state);
    return NO;
}

// Encodes the state parameter for a protocol message
- (NSString *)encodeProtocolState
{
    return [[[NSMutableDictionary dictionaryWithObjectsAndKeys:[_requestParams authority], @"a", [_requestParams resource], @"r", _scope, @"s", nil]
             adURLFormEncode] adBase64UrlEncode];
}

//Generates the query string, encoding the state:
- (NSString*)generateQueryStringForRequestType:(NSString*)requestType
{
    NSString* state = [self encodeProtocolState];
    NSString* queryParams = nil;
    
    NSString *udidString = [[NSUUID UUID] UUIDString];
        
    // Start the web navigation process for the Implicit grant profile.
    NSMutableString* startUrl = [NSMutableString stringWithFormat:@"%@?%@=%@&%@=%@&%@=%@&%@=%@&%@=%@",
                                 [_context.tokenEndpoint stringByAppendingString:OIDC_OAUTH2_AUTHORIZE_SUFFIX],
                                 OAUTH2_RESPONSE_TYPE, requestType,
                                 OAUTH2_CLIENT_ID, [[_requestParams clientId] adUrlFormEncode],
                                 OAUTH2_NONCE, udidString,
                                 OAUTH2_REDIRECT_URI, [[_requestParams redirectUri] adUrlFormEncode],
                                 OAUTH2_STATE, state];
    
    //[startUrl appendFormat:@"&%@", [[OIDCLogger oidcId] adURLFormEncode]];
    
//    if ([_requestParams identifier] && [[_requestParams identifier] isDisplayable] && ![NSString adIsStringNilOrBlank:[_requestParams identifier].userId])
//    {
//        [startUrl appendFormat:@"&%@=%@", OAUTH2_LOGIN_HINT, [[_requestParams identifier].userId adUrlFormEncode]];
//    }
//    NSString* promptParam = [OIDCAuthenticationContext getPromptParameter:_promptBehavior];
//    if (promptParam)
//    {
//        //Force the server to ignore cookies, by specifying explicitly the prompt behavior:
//        [startUrl appendString:[NSString stringWithFormat:@"&prompt=%@", promptParam]];
//    }
    
    //[startUrl appendString:@"&haschrome=1"]; //to hide back button in UI
    
    if (![NSString adIsStringNilOrBlank:_queryParams])
    {//Append the additional query parameters if specified:
        queryParams = _queryParams.adTrimmedString;
        
        //Add the '&' for the additional params if not there already:
        if ([queryParams hasPrefix:@"&"])
        {
            [startUrl appendString:queryParams];
        }
        else
        {
            [startUrl appendFormat:@"&%@", queryParams];
        }
    }
    
    if (![NSString adIsStringNilOrBlank:_claims])
    {
        NSString *claimsParam = _claims.adTrimmedString;
        [startUrl appendFormat:@"&claims=%@", claimsParam];
    }
    
    if ([_context.responseType hasPrefix:@"code"])
    {
        [startUrl appendFormat:@"&%@=%@", OAUTH2_CODE_CHALLENGE, [self getCodeChallenge]];
        [startUrl appendFormat:@"&%@=%@", OAUTH2_CODE_CHALLENGE_METHOD, @"S256"];
    }
    
    return startUrl;
}

- (void)launchWebView:(NSString*)startUrl
      completionBlock:(void (^)(OIDCAuthenticationError*, NSURL*))completionBlock
{
    [[OIDCWebAuthController sharedInstance] start:[NSURL URLWithString:startUrl]
                                            end:[NSURL URLWithString:[_requestParams redirectUri]]
                                    refreshCred:_refreshTokenCredential
#if TARGET_OS_IPHONE
                                         parent:_context.parentController
                                     fullScreen:[OIDCAuthenticationSettings sharedInstance].enableFullScreen
#endif
                                        webView:_context.webView
                                        context:_requestParams
                                     completion:completionBlock];
}

- (NSString*)getCodeVerifier
{
    
    //https://auth0.com/docs/get-started/authentication-and-authorization-flow/call-your-api-using-the-authorization-code-flow-with-pkce#create-code-challenge
    if ([NSString adIsStringNilOrBlank:_code_verifier])
    {
        NSMutableData *data = [NSMutableData dataWithLength:32];
        int result __attribute__((unused)) = SecRandomCopyBytes(kSecRandomDefault, 32, data.mutableBytes);
        _code_verifier = [[[[data base64EncodedStringWithOptions:0]
                                stringByReplacingOccurrencesOfString:@"+" withString:@"-"]
                                stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
                                stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"="]];
    }
    return _code_verifier;
}

- (NSString*)getCodeChallenge
{
    NSString *codeVerifier = [self getCodeVerifier];
    
    // Dependency: Apple Common Crypto library
    // http://opensource.apple.com//source/CommonCrypto
    
    u_int8_t buffer[CC_SHA256_DIGEST_LENGTH * sizeof(u_int8_t)];
    memset(buffer, 0x0, CC_SHA256_DIGEST_LENGTH);
    NSData *data = [codeVerifier dataUsingEncoding:NSUTF8StringEncoding];
    CC_SHA256([data bytes], (CC_LONG)[data length], buffer);
    NSData *hash = [NSData dataWithBytes:buffer length:CC_SHA256_DIGEST_LENGTH];
    NSString *challenge = [[[[hash base64EncodedStringWithOptions:0]
                             stringByReplacingOccurrencesOfString:@"+" withString:@"-"]
                             stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
                             stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"="]];
    
    return challenge;
}

//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCode:(OIDCAuthorizationCodeCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    [self ensureRequest];
    
    OIDC_LOG_VERBOSE_F(@"Requesting authorization code.", _requestParams.correlationId, @"Requesting authorization code for resource: %@", _requestParams.resource);
    
    NSString* responseType = _context.responseType ? _context.responseType : OAUTH2_ID_TOKEN;
    NSString* startUrl = [self generateQueryStringForRequestType:responseType]; // Looks like this method is incorrectly named??
    
    void(^requestCompletion)(OIDCAuthenticationError *error, NSURL *end) = ^void(OIDCAuthenticationError *error, NSURL *end)
    {
        [OIDCAuthenticationRequest releaseExclusionLock]; // Allow other operations that use the UI for credentials.
         
         NSString* code = nil;
         if (!error)
         {
             
             if ([[[end scheme] lowercaseString] isEqualToString:@"oidcauth"]) {
#if OIDC_BROKER
                 
                 NSString* host = [end host];
                 if ([host isEqualToString:@"cordovaplugin.oidc.brokerplugin"] || [host isEqualToString:@"code"])
                 {
                     NSDictionary* queryParams = [end adQueryParameters];
                     code = [queryParams objectForKey:OAUTH2_CODE];
                 }
                 else
                 {
                     NSDictionary* userInfo = @{
                                                @"username": [[NSDictionary adURLFormDecode:[end query]] valueForKey:@"username"],
                                                };
                     NSError* err = [NSError errorWithDomain:OIDCAuthenticationErrorDomain
                                                        code:OIDC_ERROR_SERVER_WPJ_REQUIRED
                                                    userInfo:userInfo];
                     error = [OIDCAuthenticationError errorFromNSError:err errorDetails:@"work place join is required" correlationId:_requestParams.correlationId];
                 }
#else
                 code = end.absoluteString;
#endif
             }
             else
             {
                 //Try both the URL and the fragment parameters:
                 NSDictionary *parameters = [end adFragmentParameters];
                 if ( parameters.count == 0 )
                 {
                     parameters = [end adQueryParameters];
                 }
                 
                 //OAuth2 error may be passed by the server:
                 error = [OIDCAuthenticationContext errorFromDictionary:parameters errorCode:OIDC_ERROR_SERVER_AUTHORIZATION_CODE];
                 if (!error)
                 {
                     //Note that we do not enforce the state, just log it:
                     [self verifyStateFromDictionary:parameters]; 
                     if ([responseType isEqualToString:@"token"] || [responseType isEqualToString:@"id_token"]) {
                         code = [parameters objectForKey:@"id_token"];
                         if ([NSString adIsStringNilOrBlank:code]){
                             code = [parameters objectForKey:@"access_token"];
                         }
                     }
                     else {
                         code = [parameters objectForKey:responseType]; // this may be an authorization code or access token depending on responseType
                     }
                     
                     if ([NSString adIsStringNilOrBlank:code])
                     {
                         error = [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_SERVER_AUTHORIZATION_CODE
                                                                        protocolCode:nil
                                                                        errorDetails:@"The authorization server did not return a valid authorization code."
                                                                       correlationId:[self->_requestParams correlationId]];
                     }
                 }
             }
         }
         
         completionBlock(code, error);
     };
    
    // If this request doesn't allow us to attempt to grab a code silently (using
    // a potential SSO cookie) then jump straight to the web view.
    if (!_allowSilent)
    {
        [self launchWebView:startUrl
            completionBlock:requestCompletion];
    }
    else
    {
        NSMutableDictionary* requestData = nil;
        requestData = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                       [_requestParams clientId], OAUTH2_CLIENT_ID,
                       [_requestParams redirectUri], OAUTH2_REDIRECT_URI,
                       [_requestParams resource], OAUTH2_RESOURCE,
                       OAUTH2_CODE, OAUTH2_RESPONSE_TYPE,
                       @"1", @"nux",
                       @"none", @"prompt", nil];
        
        if (_scope)
        {
            [requestData setObject:_scope forKey:OAUTH2_SCOPE];
        }
        
        if ([_requestParams identifier] && [[_requestParams identifier] isDisplayable] && ![NSString adIsStringNilOrBlank:[_requestParams identifier].userId])
        {
            [requestData setObject:_requestParams.identifier.userId forKey:OAUTH2_LOGIN_HINT];
        }
        
        NSURL* reqURL = [NSURL URLWithString:[_context.tokenEndpoint stringByAppendingString:OIDC_OAUTH2_AUTHORIZE_SUFFIX]];
        OIDCWebAuthRequest* req = [[OIDCWebAuthRequest alloc] initWithURL:reqURL
                                                              context:_requestParams];
        [req setIsGetRequest:YES];
        [req setRequestDictionary:requestData];
        [req sendRequest:^(OIDCAuthenticationError *error, NSDictionary * parameters)
         {
             if (error)
             {
                 requestCompletion(error, nil);
                 [req invalidate];
                 return;
             }
             
             NSURL* endURL = nil;
             
             //OAuth2 error may be passed by the server
             endURL = [parameters objectForKey:@"url"];
             if (!endURL)
             {
                 // If the request was not silent only then launch the webview
                 if (!_silent)
                 {
                     [self launchWebView:startUrl
                         completionBlock:requestCompletion];
                     return;
                 }
                 
                 // Otherwise error out
                 error = [OIDCAuthenticationContext errorFromDictionary:parameters errorCode:OIDC_ERROR_SERVER_AUTHORIZATION_CODE];
             }
             
             requestCompletion(error, endURL);
             [req invalidate];
         }];
    }
}

@end
