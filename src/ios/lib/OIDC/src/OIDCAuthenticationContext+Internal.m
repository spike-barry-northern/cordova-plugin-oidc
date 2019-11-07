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
#import "OIDCUserIdentifier.h"
#import "OIDCTokenCacheItem+Internal.h"
#import "OIDCHelpers.h"

NSString* const OIDCUnknownError = @"Uknown error.";
NSString* const OIDCCredentialsNeeded = @"The user credentials are needed to obtain access token. Please call the non-silent acquireTokenWithResource methods.";
NSString* const OIDCInteractionNotSupportedInExtension = @"Interaction is not supported in an app extension.";
NSString* const OIDCServerError = @"The authentication server returned an error: %@.";
NSString* const OIDCBrokerAppIdentifier = @"com.cordovaplugin.azureadauthenticator";
NSString* const OIDCRedirectUriInvalidError = @"Your AuthenticationContext is configured to allow brokered authentication but your redirect URI is not setup properly. Make sure your redirect URI is in the form of <app-scheme>://<bundle-id> (e.g. \"x-msauth-testapp://com.cordovaplugin.oidc.testapp\") and that the \"app-scheme\" you choose is registered in your application's info.plist.";

@implementation OIDCAuthenticationContext (Internal)

- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
             tokenCache:(id<OIDCTokenCacheDataSource>)tokenCache
                  error:(OIDCAuthenticationError *__autoreleasing *)error
{
    API_ENTRY;
    if (!(self = [super init]))
    {
        return nil;
    }
    
    NSString* extractedAuthority = [OIDCHelpers canonicalizeAuthority:authority];
    if (!extractedAuthority)
    {
        RETURN_ON_INVALID_ARGUMENT(!extractedAuthority, authority, nil);
    }
    
    _authority = extractedAuthority;
    _validateAuthority = validateAuthority;
    _credentialsType = OIDC_CREDENTIALS_EMBEDDED;
    _extendedLifetimeEnabled = NO;
    [self setTokenCacheStore:tokenCache];
    
    return self;
}

/*! Verifies that the string parameter is not nil or empty. If it is,
 the method generates an error and set it to an authentication result.
 Then the method calls the callback with the result.
 The method returns if the argument is valid. If the method returns false,
 the calling method should return. */
+ (BOOL)checkAndHandleBadArgument:(NSObject *)argumentValue
                     argumentName:(NSString *)argumentName
                    correlationId:(NSUUID *)correlationId
                  completionBlock:(OIDCAuthenticationCallback)completionBlock
{
    if (!argumentValue || ([argumentValue isKindOfClass:[NSString class]] && [NSString adIsStringNilOrBlank:(NSString*)argumentValue]))
    {
        OIDCAuthenticationError* argumentError = [OIDCAuthenticationError errorFromArgument:argumentValue argumentName:argumentName correlationId:correlationId];
        OIDCAuthenticationResult* result = [OIDCAuthenticationResult resultFromError:argumentError];
        completionBlock(result);//Call the callback to tell about the result
        return NO;
    }
    else
    {
        return YES;
    }
}

+ (BOOL)handleNilOrEmptyAsResult:(NSObject*)argumentValue
                    argumentName:(NSString*)argumentName
            authenticationResult:(OIDCAuthenticationResult**)authenticationResult
{
    if (!argumentValue || ([argumentValue isKindOfClass:[NSString class]] && [NSString adIsStringNilOrBlank:(NSString*)argumentValue]))
    {
        OIDCAuthenticationError* argumentError = [OIDCAuthenticationError errorFromArgument:argumentValue argumentName:argumentName correlationId:nil];
        *authenticationResult = [OIDCAuthenticationResult resultFromError:argumentError];
        return NO;
    }
    
    return YES;
}
//Obtains a protocol error from the response:
+ (OIDCAuthenticationError*)errorFromDictionary:(NSDictionary*)dictionary
                                    errorCode:(OIDCErrorCode)errorCode
{
    //First check for explicit OAuth2 protocol error:
    NSString* serverOAuth2Error = [dictionary objectForKey:OAUTH2_ERROR];
    if (![NSString adIsStringNilOrBlank:serverOAuth2Error])
    {
        NSString* errorDetails = [dictionary objectForKey:OAUTH2_ERROR_DESCRIPTION];
        // Error response from the server
        NSUUID* correlationId = [dictionary objectForKey:OAUTH2_CORRELATION_ID_RESPONSE] ?
                                [[NSUUID alloc] initWithUUIDString:[dictionary objectForKey:OAUTH2_CORRELATION_ID_RESPONSE]]:
                                nil;
        return [OIDCAuthenticationError OAuthServerError:serverOAuth2Error description:errorDetails code:errorCode correlationId:correlationId];
    }
    
    return nil;
}

//Returns YES if we shouldn't attempt other means to get access token.
//
+ (BOOL)isFinalResult:(OIDCAuthenticationResult*)result
{
    if (!result)
    {
        return NO;
    }
    
    // Successful results are final results!
    if (result.status == OIDC_SUCCEEDED)
    {
        return YES;
    }
    
    // Protocol Code is used for OAuth errors (and should only be used for OAuth errors...). If we
    // received an OAuth error that means that the server is up and responsive, just that something
    // about the token was bad.
    if (result.error && !result.error.protocolCode)
    {
        return YES;
    }
    
    return NO;
}

//Translates the OIDCPromptBehavior into prompt query parameter. May return nil, if such
//parameter is not needed.
+ (NSString*)getPromptParameter:(OIDCPromptBehavior)prompt
{
    switch (prompt) {
        case OIDC_PROMPT_ALWAYS:
        case OIDC_FORCE_PROMPT:
            return @"login";
        case OIDC_PROMPT_REFRESH_SESSION:
            return @"refresh_session";
        default:
            return nil;
    }
}

+ (BOOL)isForcedAuthorization:(OIDCPromptBehavior)prompt
{
    //If prompt parameter needs to be passed, re-authorization is needed.
    return [OIDCAuthenticationContext getPromptParameter:prompt] != nil;
}

- (BOOL)hasCacheStore
{
    return self.tokenCacheStore != nil;
}

//Used in the flows, where developer requested an explicit user. The method compares
//the user for the obtained tokens (if provided by the server). If the user is different,
//an error result is returned. Returns the same result, if no issues are found.
+ (OIDCAuthenticationResult*)updateResult:(OIDCAuthenticationResult*)result
                                 toUser:(OIDCUserIdentifier*)userId
{
    if (!result)
    {
        OIDCAuthenticationError* error =
        [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_DEVELOPER_INVALID_ARGUMENT
                                               protocolCode:nil
                                               errorDetails:@"OIDCAuthenticationResult is nil"
                                              correlationId:nil];
        return [OIDCAuthenticationResult resultFromError:error correlationId:[result correlationId]];
    }
    
    if (OIDC_SUCCEEDED != result.status || !userId || [NSString adIsStringNilOrBlank:userId.userId] || userId.type == OptionalDisplayableId)
    {
        //No user to compare - either no specific user id requested, or no specific userId obtained:
        return result;
    }
    
    OIDCUserInformation* userInfo = [[result tokenCacheItem] userInformation];
    
    if (!userInfo || ![userId userIdMatchString:userInfo])
    {
        // TODO: This behavior is questionable. Look into removing.
        return result;
    }
    
    if (![OIDCUserIdentifier identifier:userId matchesInfo:userInfo])
    {
        OIDCAuthenticationError* error =
        [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_SERVER_WRONG_USER
                                               protocolCode:nil
                                               errorDetails:@"Different user was returned by the server then specified in the acquireToken call. If this is a new sign in use and OIDCUserIdentifier is of OptionalDisplayableId type, pass in the userId returned on the initial authentication flow in all future acquireToken calls."
                                              correlationId:nil];
        return [OIDCAuthenticationResult resultFromError:error correlationId:[result correlationId]];
    }
    
    return result;
}

@end
