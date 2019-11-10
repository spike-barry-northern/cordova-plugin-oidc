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

#import "OIDCWebRequest.h"

#import "OIDCAuthenticationSettings.h"
#import "OIDCAuthorityValidation.h"
#import "OIDCErrorCodes.h"
#import "OIDCHelpers.h"
#import "OIDCLogger+Internal.h"
#import "OIDCOAuth2Constants.h"
#import "OIDCTelemetry.h"
#import "OIDCTelemetry+Internal.h"
#import "OIDCTelemetryHttpEvent.h"
#import "OIDCTelemetryEventStrings.h"
#import "OIDCURLProtocol.h"
#import "OIDCWebResponse.h"

#import "NSURL+OIDCExtensions.h"
#import "NSString+OIDCHelperMethods.h"


@interface OIDCWebRequest ()

- (void)completeWithError:(NSError *)error andResponse:(OIDCWebResponse *)response;
- (void)send;

@end

@implementation OIDCWebRequest

#pragma mark - Properties

@synthesize URL      = _requestURL;
@synthesize timeout  = _timeout;
@synthesize isGetRequest = _isGetRequest;
@synthesize correlationId = _correlationId;
@synthesize telemetryRequestId = _telemetryRequestId;
@synthesize session = _session;

- (NSData *)body
{
    return _requestData;
}

- (void)setBody:(NSData *)body
{
    if ( body != nil )
    {
        
        if (_requestData == body)
        {
            return;
        }
        _requestData = [body copy];
        
        // Add default HTTP Headers to the request: Expect
        // Note that we don't bother with Expect because iOS does not support it
        //[_requestHeaders setValue:@"100-continue" forKey:@"Expect"];
    }
}

#pragma mark - Initialization

- (id)initWithURL:(NSURL *)requestURL
          context:(id<OIDCRequestContext>)context
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _requestURL        = [requestURL copy];
    _requestHeaders    = [[NSMutableDictionary alloc] init];
    
    // Default timeout for OIDCWebRequest is 30 seconds
    _timeout           = [[OIDCAuthenticationSettings sharedInstance] requestTimeOut];
    
    _correlationId     = context.correlationId;
    
    _telemetryRequestId = context.telemetryRequestId;
    
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    _session = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:nil];
    
    return self;
}

// Cleans up and then calls the completion handler
- (void)completeWithError:(NSError *)error andResponse:(OIDCWebResponse *)response
{
    // Cleanup
    _response       = nil;
    _responseData   = nil;

    _task           = nil;
    
    [self stopTelemetryEvent:error response:response];
    _completionHandler(error, response);
}

- (void)send:(void (^)(NSError *, OIDCWebResponse *))completionHandler
{
    _completionHandler = [completionHandler copy];
    _response          = nil;
    _responseData      = [[NSMutableData alloc] init];
    
    [self send];
}

- (void)resend
{
    _response          = nil;
    _responseData      = [[NSMutableData alloc] init];

    [self send];
}

- (void)send
{
    [[OIDCTelemetry sharedInstance] startEvent:_telemetryRequestId eventName:OIDC_TELEMETRY_EVENT_HTTP_REQUEST];
    [_requestHeaders addEntriesFromDictionary:[OIDCLogger oidcId]];
    //Correlation id:
    if (_correlationId)
    {
        [_requestHeaders addEntriesFromDictionary:
         @{
           OAUTH2_CORRELATION_ID_REQUEST:@"true",
           OAUTH2_CORRELATION_ID_REQUEST_VALUE:[_correlationId UUIDString]
           }];
    }
    // If there is request data, then set the Content-Length header
    if ( _requestData != nil )
    {
        [_requestHeaders setValue:[NSString stringWithFormat:@"%ld", (unsigned long)_requestData.length] forKey:@"Content-Length"];
    }
    
    NSURL* requestURL = [OIDCHelpers addClientVersionToURL:_requestURL];
    requestURL = [[OIDCAuthorityValidation sharedInstance] networkUrlForAuthority:requestURL context:self];
    
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:requestURL
                                                                cachePolicy:NSURLRequestReloadIgnoringCacheData
                                                            timeoutInterval:_timeout];
    
    request.HTTPMethod          = _isGetRequest ? @"GET" : @"POST";
    request.allHTTPHeaderFields = _requestHeaders;
    request.HTTPBody            = _requestData;
    
    [OIDCURLProtocol addContext:self toRequest:request];
    
    _task = [_session dataTaskWithRequest:request];
    [_task resume];
}

- (void)invalidate
{
    [_session finishTasksAndInvalidate];
    _completionHandler = nil;
}

#pragma mark - NSURLSession delegates
- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    (void)session;
    (void)challenge;
    
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
    (void)session;
    (void)task;
    
    if (error == nil)
    {
        //
        // NOTE: There is a race condition between this method and the challenge handling methods
        //       dependent on the the challenge processing that the application performs.
        //
        NSAssert( _response != nil, @"No HTTP Response available" );
        
        OIDCWebResponse* response = [[OIDCWebResponse alloc] initWithResponse:_response data:_responseData];
        [self completeWithError:nil andResponse:response];
    }
    else
    {
        [self completeWithError:error andResponse:nil];
    }
}

#pragma mark - NSURLSessionDataDelegate
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler
{
    (void)session;
    (void)dataTask;
  
    _response = (NSHTTPURLResponse *)response;
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data
{
    (void)session;
    (void)dataTask;
    
    [_responseData appendData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler
{
    (void)session;
    (void)response;
    (void)task;
    
    NSURL* requestURL = [request URL];
    NSURL* modifiedURL = [OIDCHelpers addClientVersionToURL:requestURL];
    
    if (modifiedURL == requestURL)
    {
        completionHandler(request);
        return;
    }

    NSMutableURLRequest* mutableRequest = [NSMutableURLRequest requestWithURL:modifiedURL];
    [OIDCURLProtocol addContext:self toRequest:mutableRequest];
    
    completionHandler(mutableRequest);
  
}

- (void)stopTelemetryEvent:(NSError *)error
                  response:(OIDCWebResponse *)response
{
    OIDCTelemetryHttpEvent* event = [[OIDCTelemetryHttpEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_HTTP_REQUEST requestId:_telemetryRequestId correlationId:_correlationId];
    
    [event setHttpMethod:_isGetRequest ? @"GET" : @"POST"];
    [event setHttpPath:[NSString stringWithFormat:@"%@://%@/%@", _requestURL.scheme, _requestURL.host, _requestURL.path]];
    [event setHttpRequestIdHeader:[response.headers objectForKey:OAUTH2_CORRELATION_ID_REQUEST_VALUE]];
    if (error)
    {
        [event setHttpErrorCode:[NSString stringWithFormat: @"%ld", (long)[error code]]];
        [event setHttpErrorDomain:[error domain]];
    }
    else if (response)
    {
        [event setHttpResponseCode:[NSString stringWithFormat: @"%ld", (long)[response statusCode]]];
    }
    
    [event setOAuthErrorCode:response];
    [event setClientTelemetry:[response headers][OIDC_CLIENT_TELEMETRY]];
    
    [event setHttpRequestQueryParams:_requestURL.query];
    
    [[OIDCTelemetry sharedInstance] stopEvent:_telemetryRequestId event:event];
}

- (void)addToHeadersFromDictionary:(NSDictionary *)headers
{
    [_requestHeaders addEntriesFromDictionary:headers];
}

- (void) setAuthorizationHeader:(NSString *)header
{
    [_requestHeaders setObject:header forKey:@"Authorization"];
}
@end
