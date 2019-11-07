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
#import "OIDCAuthenticationResult.h"
#import "OIDCAuthenticationResult+Internal.h"
#import "OIDCTokenCacheItem+Internal.h"
#import "OIDCOAuth2Constants.h"
#import "OIDCUserInformation.h"

@implementation OIDCAuthenticationResult (Internal)

- (id)initWithCancellation:(NSUUID*)correlationId
{
    OIDCAuthenticationError* error = [OIDCAuthenticationError errorFromCancellation:correlationId];
    
    return [self initWithError:error status:OIDC_USER_CANCELLED correlationId:correlationId];
}

-(id) initWithItem: (OIDCTokenCacheItem*) item
multiResourceRefreshToken: (BOOL) multiResourceRefreshToken
     correlationId: (NSUUID*) correlationId
{
    self = [super init];
    if (self)
    {
        // Non ObjC Objects
        _status = OIDC_SUCCEEDED;
        _multiResourceRefreshToken = multiResourceRefreshToken;
        
        // ObjC Objects
        _tokenCacheItem = item;
        _correlationId = correlationId;
    }
    return self;
}

- (id)initWithError:(OIDCAuthenticationError *)error
             status:(OIDCAuthenticationResultStatus)status
      correlationId:(NSUUID *)correlationId
{
    THROW_ON_NIL_ARGUMENT(error);
    
    self = [super init];
    if (self)
    {
        _status = status;
        _error = error;
        _correlationId = correlationId;
    }
    return self;
}

+ (OIDCAuthenticationResult*)resultFromTokenCacheItem:(OIDCTokenCacheItem *)item
                               multiResourceRefreshToken:(BOOL)multiResourceRefreshToken
                                           correlationId:(NSUUID *)correlationId
{
    if (!item)
    {
        OIDCAuthenticationError* error = [OIDCAuthenticationError unexpectedInternalError:@"OIDCAuthenticationResult was created with nil token item."
                                                                        correlationId:correlationId];
        return [OIDCAuthenticationResult resultFromError:error];
    }
    
    OIDCAuthenticationResult* result = [[OIDCAuthenticationResult alloc] initWithItem:item
                                                        multiResourceRefreshToken:multiResourceRefreshToken
                                                                    correlationId:correlationId];
    
    return result;
}

+(OIDCAuthenticationResult*) resultFromError: (OIDCAuthenticationError*) error
{
    return [self resultFromError:error correlationId:nil];
}

+(OIDCAuthenticationResult*) resultFromError: (OIDCAuthenticationError*) error
                             correlationId: (NSUUID*) correlationId
{
    OIDCAuthenticationResult* result = [[OIDCAuthenticationResult alloc] initWithError:error
                                                                            status:OIDC_FAILED
                                                                     correlationId:correlationId];
    
    return result;
}

+ (OIDCAuthenticationResult*)resultFromParameterError:(NSString *)details
{
    return [self resultFromParameterError:details correlationId:nil];
}

+ (OIDCAuthenticationResult*)resultFromParameterError:(NSString *)details
                                      correlationId:(NSUUID*)correlationId
{
    OIDCAuthenticationError* adError = [OIDCAuthenticationError invalidArgumentError:details correlationId:correlationId];
    OIDCAuthenticationResult* result = [[OIDCAuthenticationResult alloc] initWithError:adError
                                                                            status:OIDC_FAILED
                                                                     correlationId:correlationId];
    
    return result;
}

+ (OIDCAuthenticationResult*)resultFromCancellation
{
    return [self resultFromCancellation:nil];
}

+ (OIDCAuthenticationResult*)resultFromCancellation:(NSUUID *)correlationId
{
    OIDCAuthenticationResult* result = [[OIDCAuthenticationResult alloc] initWithCancellation:correlationId];
    return result;
}

+ (OIDCAuthenticationResult*)resultForNoBrokerResponse
{
    NSError* nsError = [NSError errorWithDomain:OIDCBrokerResponseErrorDomain
                                           code:OIDC_ERROR_TOKENBROKER_UNKNOWN
                                       userInfo:nil];
    OIDCAuthenticationError* error = [OIDCAuthenticationError errorFromNSError:nsError
                                                              errorDetails: @"No broker response received."
                                                             correlationId:nil];
    return [OIDCAuthenticationResult resultFromError:error correlationId:nil];
}

+ (OIDCAuthenticationResult*)resultForBrokerErrorResponse:(NSDictionary*)response
{
    NSUUID* correlationId = nil;
    NSString* uuidString = [response valueForKey:OAUTH2_CORRELATION_ID_RESPONSE];
    if (uuidString)
    {
        correlationId = [[NSUUID alloc] initWithUUIDString:[response valueForKey:OAUTH2_CORRELATION_ID_RESPONSE]];
    }
    
    // Otherwise parse out the error condition
    OIDCAuthenticationError* error = nil;
    
    NSString* errorDetails = [response valueForKey:OAUTH2_ERROR_DESCRIPTION];
    if (!errorDetails)
    {
        errorDetails = @"Broker did not provide any details";
    }
        
    NSString* strErrorCode = [response valueForKey:@"error_code"];
    NSInteger errorCode = OIDC_ERROR_TOKENBROKER_UNKNOWN;
    if (strErrorCode && ![strErrorCode isEqualToString:@"0"])
    {
        errorCode = [strErrorCode integerValue];
    }
    
    NSString* protocolCode = [response valueForKey:@"protocol_code"];
    if (!protocolCode)
    {
        // Older brokers used to send the protocol code as "code" and the error code not at all
        protocolCode = [response valueForKey:@"code"];
    }
    
    if (![NSString adIsStringNilOrBlank:protocolCode])
    {
       
        error = [OIDCAuthenticationError errorFromAuthenticationError:errorCode
                                                       protocolCode:protocolCode
                                                       errorDetails:errorDetails
                                                      correlationId:correlationId];
    }
    else
    {
        NSError* nsError = [NSError errorWithDomain:OIDCBrokerResponseErrorDomain
                                               code:errorCode
                                           userInfo:nil];
        error = [OIDCAuthenticationError errorFromNSError:nsError errorDetails:errorDetails correlationId:correlationId];
    }
    
    return [OIDCAuthenticationResult resultFromError:error correlationId:correlationId];

}

+ (OIDCAuthenticationResult *)resultFromBrokerResponse:(NSDictionary *)response
{
    if (!response)
    {
        return [self resultForNoBrokerResponse];
    }
    
    if ([response valueForKey:OAUTH2_ERROR_DESCRIPTION])
    {
        return [self resultForBrokerErrorResponse:response];
    }
    
    NSUUID* correlationId =  nil;
    NSString* correlationIdStr = [response valueForKey:OAUTH2_CORRELATION_ID_RESPONSE];
    if (correlationIdStr)
    {
        correlationId = [[NSUUID alloc] initWithUUIDString:correlationIdStr];
    }

    OIDCTokenCacheItem* item = [OIDCTokenCacheItem new];
    [item setAccessTokenType:@"Bearer"];
    BOOL isMRRT = [item fillItemWithResponse:response];
    OIDCAuthenticationResult* result = [[OIDCAuthenticationResult alloc] initWithItem:item
                                                        multiResourceRefreshToken:isMRRT
                                                                    correlationId:correlationId];
    return result;
    
}

- (void)setExtendedLifeTimeToken:(BOOL)extendedLifeTimeToken;
{
    _extendedLifeTimeToken = extendedLifeTimeToken;
}

@end
