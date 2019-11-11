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
#import "OIDCAuthenticationParameters.h"
#import "OIDCAuthenticationParameters+Internal.h"

NSString* const OidcOAuth2_Bearer  = @"Bearer";
NSString* const OidcOAuth2_Authenticate_Header = @"WWW-Authenticate";
NSString* const OidcOAuth2_Authorization_Uri  = @"authorization_uri";
NSString* const OidcOAuth2_Resource_Id = @"resource_id";

NSString* const OidcMissingHeader = @"The authentication header '%@' is missing in the Unauthorized (401) response. Make sure that the resouce server supports OAuth2 protocol.";
NSString* const OidcMissingOrInvalidAuthority = @"The authentication header '%@' in the Unauthorized (401) response does not contain valid '%@' parameter. Make sure that the resouce server supports OAuth2 protocol.";
NSString* const OidcInvalidHeader = @"The authentication header '%@' for the Unauthorized (401) response cannot be parsed. Header value: %@";
NSString* const OidcConnectionError = @"Connection error: %@";
NSString* const OidcInvalidResponse = @"Missing or invalid Url response.";
NSString* const OidcUnauthorizedHTTStatusExpected = @"Unauthorized (401) HTTP status code is expected, but the actual status code is %d";
const unichar Quote = '\"';
//The regular expression that matches the Bearer contents:
NSString* const OidcRegularExpression = @"^Bearer\\s+([^,\\s=\"]+?)=\"([^\"]*?)\"\\s*(?:,\\s*([^,\\s=\"]+?)=\"([^\"]*?)\"\\s*)*$";
NSString* const OidcExtractionExpression = @"\\s*([^,\\s=\"]+?)=\"([^\"]*?)\"";

@implementation OIDCAuthenticationParameters (Internal)


- (id)initInternalWithParameters:(NSDictionary *)extractedParameters
                           error:(OIDCAuthenticationError * __autoreleasing *)error;

{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    if (!extractedParameters)
    {
        return nil;
    }
    
    NSString* authority = [extractedParameters objectForKey:OidcOAuth2_Authorization_Uri];
    NSURL* testUrl = [NSURL URLWithString:authority];//Nil argument returns nil
    if (!testUrl)
    {
        NSString* errorDetails = [NSString stringWithFormat:OidcMissingOrInvalidAuthority,
                                  OidcOAuth2_Authenticate_Header, OidcOAuth2_Authorization_Uri];
        OIDCAuthenticationError* adError = [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_SERVER_AUTHENTICATE_HEOIDCER_BOIDC_FORMAT
                                                                                protocolCode:nil
                                                                                errorDetails:errorDetails
                                                                               correlationId:nil];
        if (error)
        {
            *error = adError;
        }
        return nil;
    }
    
    _extractedParameters = extractedParameters;
    _authority = authority;
    _resource = [_extractedParameters objectForKey:OidcOAuth2_Resource_Id];
    return self;
}

//Generates and returns an error
+ (OIDCAuthenticationError *)invalidHeader:(NSString *)headerContents
{
    NSString* errorDetails = [NSString stringWithFormat:OidcInvalidHeader,
     OidcOAuth2_Authenticate_Header, headerContents];
    return [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_SERVER_AUTHENTICATE_HEOIDCER_BOIDC_FORMAT
                                                  protocolCode:nil
                                                   errorDetails:errorDetails
                                                  correlationId:nil];
}

+ (NSDictionary *)extractChallengeParameters:(NSString *)headerContents
                                       error:(OIDCAuthenticationError * __autoreleasing *)error;
{
    NSError* rgError = nil;
    __block OIDCAuthenticationError* adError = nil;
    
    if ([NSString adIsStringNilOrBlank:headerContents])
    {
        adError = [self invalidHeader:headerContents];
    }
    else
    {
        //First check that the header conforms to the protocol:
        NSRegularExpression* overAllRegEx = [NSRegularExpression regularExpressionWithPattern:OidcRegularExpression
                                                                                      options:0
                                                                                        error:&rgError];
        if (overAllRegEx)
        {
            long matched = [overAllRegEx numberOfMatchesInString:headerContents options:0 range:NSMakeRange(0, headerContents.length)];
            if (!matched)
            {
                adError = [self invalidHeader:headerContents];
            }
            else
            {
                //Once we know that the header is in the right format, the regex below will extract individual
                //name-value pairs. This regex is not as exclusive, so it relies on the previous check
                //to guarantee correctness:
                NSRegularExpression* extractionRegEx = [NSRegularExpression regularExpressionWithPattern:OidcExtractionExpression
                                                                                                 options:0
                                                                                                   error:&rgError];
                if (extractionRegEx)
                {
                    NSMutableDictionary* parameters = [NSMutableDictionary new];
                    [extractionRegEx enumerateMatchesInString:headerContents
                                                      options:0
                                                        range:NSMakeRange(0, headerContents.length)
                                                   usingBlock:^(NSTextCheckingResult *result, NSMatchingFlags flags, BOOL *stop)
                     {
                         (void)flags;
                         (void)stop;
                         
                         //Block executed for each name-value match:
                         if (result.numberOfRanges != 3)//0: whole match, 1 - name group, 2 - value group
                         {
                             //Shouldn't happen given the explicit expressions and matches, but just in case:
                             adError = [self invalidHeader:headerContents];
                         }
                         else
                         {
                             NSRange key = [result rangeAtIndex:1];
                             NSRange value = [result rangeAtIndex:2];
                             if (key.length && value.length)
                             {
                                 [parameters setObject:[headerContents substringWithRange:value]
                                                forKey:[headerContents substringWithRange:key]];
                             }
                         }
                     }];
                    return parameters;
                }
            }
        }
    }
    
    if (rgError)
    {
        //The method below will log internally the error:
        adError =[OIDCAuthenticationError errorFromNSError:rgError errorDetails:rgError.description correlationId:nil];
    }
    
    if (error)
    {
        *error = adError;
    }
    return nil;
}

@end
