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


#import "OIDCAuthorityValidationRequest.h"
#import "OIDCOAuth2Constants.h"
#import "OIDCWebAuthRequest.h"
#import "NSDictionary+OIDCExtensions.h"

static NSString* const s_kApiVersionKey            = @"api-version";
static NSString* const s_kApiVersion               = @OIDC_AUTHORITY_VALIDATION_API_VERSION;
static NSString* const s_kAuthorizationEndPointKey = @"authorization_endpoint";

@implementation OIDCAuthorityValidationRequest

+ (void)requestMetadataWithAuthority:(NSString *)authority
                       tokenEndpoint:(NSString *)tokenEndpoint
                         trustedHost:(NSString *)trustedHost
                             context:(id<OIDCRequestContext>)context
                     completionBlock:(void (^)(NSDictionary *response, OIDCAuthenticationError *error))completionBlock
{
    NSURL *endpoint = [self urlForAuthorityValidation:authority tokenEndpoint:tokenEndpoint trustedHost:trustedHost];
    OIDCWebAuthRequest *webRequest = [[OIDCWebAuthRequest alloc] initWithURL:endpoint
                                                                 context:context];
    
    [webRequest setIsGetRequest:YES];
    [webRequest sendRequest:^(OIDCAuthenticationError *error, NSMutableDictionary *response)
    {
        if (error)
        {
            completionBlock(nil, error);
        }
        else
        {
            completionBlock(response, nil);
        }
        
        [webRequest invalidate];
    }];
}

+ (NSURL *)urlForAuthorityValidation:(NSString *)authority
                       tokenEndpoint:(NSString *)tokenEndpoint
                         trustedHost:(NSString *)trustedHost
{
    NSString *authorizationEndpoint = [tokenEndpoint stringByAppendingString:OIDC_OAUTH2_AUTHORIZE_SUFFIX];
    NSDictionary *request_data = @{s_kApiVersionKey:s_kApiVersion,
                                   s_kAuthorizationEndPointKey: authorizationEndpoint};
    
    // TODO: DB REVIEW - OAUTH2_INSTANCE_DISCOVERY_SUFFIX 
    // BARRY: extern declaration for above variable wasn't commented, only the internal definition, however,
    // the ADAL.framework defines the value, which is now the same value with a different variable name "MSID_OAUTH2_INSTANCE_DISCOVERY_SUFFIX"
    // I just removed the broken reference to fix the link error: needs review.
    NSString *endpoint = [NSString stringWithFormat:@"https://%@/%@?%@",
                          trustedHost, OAUTH2_INSTANCE_DISCOVERY_SUFFIX, [request_data adURLFormEncode]];
    
    return [NSURL URLWithString:endpoint];
}

@end
