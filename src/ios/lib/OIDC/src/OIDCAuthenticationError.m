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
#import "OIDCAuthenticationError.h"

NSString* const OIDCAuthenticationErrorDomain = @"OIDCAuthenticationErrorDomain";
NSString* const OIDCBrokerResponseErrorDomain = @"OIDCBrokerResponseErrorDomain";
NSString* const OIDCKeychainErrorDomain = @"OIDCKeychainErrorDomain";
NSString* const OIDCHTTPErrorCodeDomain = @"OIDCHTTPErrorCodeDomain";
NSString* const OIDCOAuthServerErrorDomain = @"OIDCOAuthServerErrorDomain";

NSString* const OIDCInvalidArgumentMessage = @"The argument '%@' is invalid. Value:%@";

NSString* const OIDCCancelError = @"The user has cancelled the authorization.";
NSString* const OIDCNonHttpsRedirectError = @"The server has redirected to a non-https url.";

@implementation OIDCAuthenticationError

@synthesize errorDetails = _errorDetails;
@synthesize protocolCode = _protocolCode;

- (id)init
{
    //Should not be called.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initWithDomain:(NSString *)domain
                code:(NSInteger)code
            userInfo:(NSDictionary *)dict
{
    (void)domain;
    (void)code;
    (void)dict;
    
    //Overrides the parent class and ensures that it throws. This one should not be called.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (NSString *)description
{
    NSString* superDescription = [super description];
    
    NSString* codeStr = [self getStringForErrorCode:self.code domain:self.domain];
    
    return [NSString stringWithFormat:@"Error with code: %@ Domain: %@ ProtocolCode:%@ Details:%@. Inner error details: %@",
            codeStr, self.domain, self.protocolCode, self.errorDetails, superDescription];
}

- (id)initInternalWithDomain:(NSString *)domain
                        code:(NSInteger)code
                protocolCode:(NSString *)protocolCode
                errorDetails:(NSString *)details
               correlationId:(NSUUID *)correlationId
                    userInfo:(NSDictionary *)userInfo
                       quiet:(BOOL)quiet
{
    if (!domain)
    {
        domain = @"OIDC";
    }
    
    if (!(self = [super initWithDomain:domain code:code userInfo:userInfo]))
    {
        // If we're getting nil back here we have bigger problems and the logging below is going to fail anyways.`
        return nil;
    }
    
    _errorDetails = details;
    _protocolCode = protocolCode;
    
    if (!quiet)
    {
        NSString* codeStr = [self getStringForErrorCode:code domain:domain];
        NSString* message = [NSString stringWithFormat:@"Error raised: (Domain: \"%@\" Code: %@ ProtocolCode: \"%@\" Details: \"%@\"", domain, codeStr, protocolCode, details];
        NSDictionary* logDict = nil;
        if (correlationId)
        {
            logDict = @{ @"error" : self,
                         @"correlationId" : correlationId };
        }
        else
        {
            logDict = @{ @"error" : self };
        }
        
        OIDC_LOG_ERROR_DICT(message, code, correlationId, logDict, nil);
    }
    
    return self;
}

+ (OIDCAuthenticationError *)errorWithDomainInternal:(NSString *)domain
                                              code:(NSInteger)code
                                 protocolErrorCode:(NSString *)protocolCode
                                      errorDetails:(NSString *)details
                                     correlationId:(NSUUID *)correlationId
                                          userInfo:(NSDictionary *)userInfo
{
    id obj = [[self alloc] initInternalWithDomain:domain
                                             code:code
                                     protocolCode:protocolCode
                                     errorDetails:details
                                    correlationId:correlationId
                                         userInfo:userInfo
                                            quiet:NO];
    return obj;
}

+ (OIDCAuthenticationError*)errorFromArgument:(id)argumentValue
                               argumentName:(NSString *)argumentName
                              correlationId:(NSUUID *)correlationId
{
    THROW_ON_NIL_EMPTY_ARGUMENT(argumentName);
    
    //Constructs the applicable message and return the error:
    NSString* errorMessage = [NSString stringWithFormat:OIDCInvalidArgumentMessage, argumentName, argumentValue];
    return [self errorWithDomainInternal:OIDCAuthenticationErrorDomain
                                    code:OIDC_ERROR_DEVELOPER_INVALID_ARGUMENT
                       protocolErrorCode:nil
                            errorDetails:errorMessage
                           correlationId:correlationId
                                userInfo:nil];
}

+ (OIDCAuthenticationError*)invalidArgumentError:(NSString *)details
                                 correlationId:(nullable NSUUID *)correlationId
{
    return [self errorWithDomainInternal:OIDCAuthenticationErrorDomain
                                    code:OIDC_ERROR_DEVELOPER_INVALID_ARGUMENT
                       protocolErrorCode:nil
                            errorDetails:details
                           correlationId:correlationId
                                userInfo:nil];
}

+ (OIDCAuthenticationError*)errorFromNSError:(NSError *)error
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:error.domain
                                    code:error.code
                       protocolErrorCode:nil
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:error.userInfo];
}

+ (OIDCAuthenticationError*)errorFromAuthenticationError:(NSInteger)code
                                          protocolCode:(NSString *)protocolCode
                                          errorDetails:(NSString *)errorDetails
                                              userInfo:(NSDictionary *)userInfo
                                         correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:OIDCAuthenticationErrorDomain
                                    code:code
                       protocolErrorCode:protocolCode
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:userInfo];
}

+ (OIDCAuthenticationError*)errorFromAuthenticationError:(NSInteger)code
                                          protocolCode:(NSString *)protocolCode
                                          errorDetails:(NSString *)errorDetails
                                         correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:OIDCAuthenticationErrorDomain
                                    code:code
                       protocolErrorCode:protocolCode
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:nil];
}

+ (OIDCAuthenticationError*)errorQuietWithAuthenticationError:(NSInteger)code
                                               protocolCode:(NSString*)protocolCode
                                               errorDetails:(NSString*)errorDetails
{
    OIDCAuthenticationError* error =
    [[OIDCAuthenticationError alloc] initInternalWithDomain:OIDCAuthenticationErrorDomain
                                                     code:code
                                             protocolCode:protocolCode
                                             errorDetails:errorDetails
                                            correlationId:nil
                                                 userInfo:nil
                                                    quiet:YES];
    return error;
}

+ (OIDCAuthenticationError*)unexpectedInternalError:(NSString*)errorDetails
                                    correlationId:(NSUUID *)correlationId
{
    return [self errorFromAuthenticationError:OIDC_ERROR_UNEXPECTED
                                 protocolCode:nil
                                 errorDetails:errorDetails
                                correlationId:correlationId];
}

+ (OIDCAuthenticationError*)errorFromCancellation:(NSUUID *)correlationId
{
    return [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_UI_USER_CANCEL
                                                  protocolCode:nil
                                                  errorDetails:OIDCCancelError
                                                 correlationId:correlationId];
}

+ (OIDCAuthenticationError*)errorFromNonHttpsRedirect:(NSUUID *)correlationId
{
    return [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_SERVER_NON_HTTPS_REDIRECT
                                                  protocolCode:nil
                                                  errorDetails:OIDCNonHttpsRedirectError
                                                 correlationId:correlationId];
}

+ (OIDCAuthenticationError *)keychainErrorFromOperation:(NSString *)operation
                                               status:(OSStatus)status
                                        correlationId:(NSUUID *)correlationId
{
    NSString* details = [NSString stringWithFormat:@"Keychain failed during \"%@\" operation", operation];
    
    return [self errorWithDomainInternal:OIDCKeychainErrorDomain
                                    code:status
                       protocolErrorCode:nil
                            errorDetails:details
                           correlationId:correlationId
                                userInfo:nil];
}

+ (OIDCAuthenticationError *)HTTPErrorCode:(NSInteger)code
                                    body:(NSString *)body
                           correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:OIDCHTTPErrorCodeDomain
                                    code:code
                       protocolErrorCode:nil
                            errorDetails:body
                           correlationId:correlationId
                                userInfo:nil];
}

+ (OIDCAuthenticationError *)OAuthServerError:(NSString *)protocolCode
                                description:(NSString *)description
                                       code:(NSInteger)code
                              correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:OIDCOAuthServerErrorDomain
                                    code:code
                       protocolErrorCode:protocolCode
                            errorDetails:description
                           correlationId:correlationId
                                userInfo:nil];
}

- (NSString*)getStringForErrorCode:(NSInteger)code
                              domain:(NSString *)domain
{
    //code is OIDCErrorCode enum if domain is one of following
    if ([domain isEqualToString:OIDCAuthenticationErrorDomain] ||
        [domain isEqualToString:OIDCBrokerResponseErrorDomain] ||
        [domain isEqualToString:OIDCOAuthServerErrorDomain])
    {
        return [self.class stringForOIDCErrorCode:(OIDCErrorCode)code];
    }
    return [NSString stringWithFormat:@"%ld", (long)code];
}

#define OIDC_ERROR_CODE_ENUM_CASE(_enum) case _enum: return @#_enum;

+ (NSString*)stringForOIDCErrorCode:(OIDCErrorCode)code
{
    switch (code)
    {
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SUCCEEDED);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_UNEXPECTED);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_DEVELOPER_INVALID_ARGUMENT);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_DEVELOPER_AUTHORITY_VALIDATION);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_USER_INPUT_NEEDED);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_WPJ_REQUIRED);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_OAUTH);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_REFRESH_TOKEN_REJECTED);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_WRONG_USER);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_NON_HTTPS_REDIRECT);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_INVALID_ID_TOKEN);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_MISSING_AUTHENTICATE_HEOIDCER);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_AUTHENTICATE_HEOIDCER_BOIDC_FORMAT);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_UNAUTHORIZED_CODE_EXPECTED);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_UNSUPPORTED_REQUEST);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_SERVER_AUTHORIZATION_CODE);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_CACHE_MULTIPLE_USERS);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_CACHE_VERSION_MISMATCH);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_CACHE_BOIDC_FORMAT);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_CACHE_NO_REFRESH_TOKEN);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_UI_MULTLIPLE_INTERACTIVE_REQUESTS);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_UI_NO_MAIN_VIEW_CONTROLLER);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_UI_USER_CANCEL);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_UI_NOT_ON_MAIN_THREOIDC);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_TOKENBROKER_UNKNOWN);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_TOKENBROKER_INVALID_REDIRECT_URI);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_TOKENBROKER_RESPONSE_HASH_MISMATCH);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_TOKENBROKER_RESPONSE_NOT_RECEIVED);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_TOKENBROKER_FAILED_TO_CREATE_KEY);
            OIDC_ERROR_CODE_ENUM_CASE(OIDC_ERROR_TOKENBROKER_DECRYPTION_FAILED);
            default:
                return [NSString stringWithFormat:@"%ld", (long)code];
    }
}

@end
