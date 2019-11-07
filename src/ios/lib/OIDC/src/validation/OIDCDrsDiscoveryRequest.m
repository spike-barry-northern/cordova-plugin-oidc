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


#import "OIDCDrsDiscoveryRequest.h"
#import "OIDCWebAuthRequest.h"
#import "OIDCOAuth2Constants.h"

@implementation OIDCDrsDiscoveryRequest

+ (void)requestDrsDiscoveryForDomain:(NSString *)domain
                            adfsType:(AdfsType)type
                             context:(id<OIDCRequestContext>)context
                     completionBlock:(void (^)(id result, OIDCAuthenticationError *error))completionBlock
{
    NSURL *url = [self urlForDrsDiscoveryForDomain:domain adfsType:type];
    
    OIDCWebAuthRequest *webRequest = [[OIDCWebAuthRequest alloc] initWithURL:url context:context];
    [webRequest setIsGetRequest:YES];
    [webRequest setAcceptOnlyOKResponse:YES];
    
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

+ (NSURL *)urlForDrsDiscoveryForDomain:(NSString *)domain adfsType:(AdfsType)type
{
    if (type == OIDC_OAUTH_ON_PREMS)
    {
        return [NSURL URLWithString:
                [NSString stringWithFormat:@"https://enterpriseregistration.%@/enrollmentserver/contract?api-version=1.0", domain.lowercaseString]];
    }
    else if (type == OIDC_OAUTH_CLOUD)
    {
        return [NSURL URLWithString:
                [NSString stringWithFormat:@"https://enterpriseregistration.windows.net/%@/enrollmentserver/contract?api-version=1.0", domain.lowercaseString]];
    }
    else
    {
        @throw @"unrecognized type";
    }
}

@end
