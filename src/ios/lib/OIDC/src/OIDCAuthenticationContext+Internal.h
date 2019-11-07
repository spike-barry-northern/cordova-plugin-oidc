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

//A wrapper around checkAndHandleBadArgument. Assumes that "completionMethod" is in scope:
#define HANDLE_ARGUMENT(ARG, CORRELATION_ID) \
    if (![OIDCAuthenticationContext checkAndHandleBadArgument:ARG \
                                               argumentName:TO_NSSTRING(#ARG) \
                                              correlationId:CORRELATION_ID \
                                            completionBlock:completionBlock]) \
    { \
    return; \
    }

#define CHECK_FOR_NIL(_val) \
    if (!_val) { completionBlock([OIDCAuthenticationResult resultFromError:[OIDCAuthenticationError unexpectedInternalError:@"" #_val " is nil!" correlationId:[_requestParams correlationId]]]); return; }

#import "OIDC_Internal.h"

@class OIDCUserIdentifier;
@class OIDCTokenCacheAccessor;
@protocol OIDCTokenCacheDataSource;

#import "OIDCAuthenticationContext.h"
#import "OIDCAuthenticationResult+Internal.h"
#import "OIDCOAuth2Constants.h"
#import "OIDCTokenCacheAccessor.h"

extern NSString* const OIDCUnknownError;
extern NSString* const OIDCCredentialsNeeded;
extern NSString* const OIDCInteractionNotSupportedInExtension;
extern NSString* const OIDCServerError;
extern NSString* const OIDCBrokerAppIdentifier;
extern NSString* const OIDCRedirectUriInvalidError;


@interface OIDCAuthenticationContext (Internal)

+ (BOOL)checkAndHandleBadArgument:(NSObject *)argumentValue
                     argumentName:(NSString *)argumentName
                    correlationId:(NSUUID *)correlationId
                  completionBlock:(OIDCAuthenticationCallback)completionBlock;

+ (BOOL)handleNilOrEmptyAsResult:(NSObject *)argumentValue
                    argumentName:(NSString *)argumentName
            authenticationResult:(OIDCAuthenticationResult **)authenticationResult;

+ (OIDCAuthenticationError*)errorFromDictionary:(NSDictionary *)dictionary
                                    errorCode:(OIDCErrorCode)errorCode;


- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
             tokenCache:(id<OIDCTokenCacheDataSource>)tokenCache
                  error:(OIDCAuthenticationError *__autoreleasing *)error;

+ (BOOL)isFinalResult:(OIDCAuthenticationResult *)result;

+ (NSString*)getPromptParameter:(OIDCPromptBehavior)prompt;

+ (BOOL)isForcedAuthorization:(OIDCPromptBehavior)prompt;

+ (OIDCAuthenticationResult*)updateResult:(OIDCAuthenticationResult *)result
                                 toUser:(OIDCUserIdentifier *)userId;

- (BOOL)hasCacheStore;

@end

@interface OIDCAuthenticationContext (CacheStorage)

- (void)setTokenCacheStore:(id<OIDCTokenCacheDataSource>)tokenCacheStore;
- (OIDCTokenCacheAccessor *)tokenCacheStore;

@end
