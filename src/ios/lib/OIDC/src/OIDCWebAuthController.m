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

#if TARGET_OS_IPHONE
#import "UIApplication+OIDCExtensions.h"
#import "OIDCAppExtensionUtil.h"
#endif
#import "NSDictionary+OIDCExtensions.h"

#import "OIDCWebAuthController+Internal.h"

#import "OIDCAuthenticationViewController.h"
#import "OIDCAuthenticationSettings.h"
#import "OIDCAuthorityValidation.h"
#import "OIDCCustomHeaderHandler.h"
#import "OIDCHelpers.h"
#import "OIDCNTLMHandler.h"
#import "OIDCOAuth2Constants.h"
#import "OIDCPkeyAuthHelper.h"
#import "OIDCURLProtocol.h"
#import "OIDCWebAuthDelegate.h"
#import "OIDCWorkPlaceJoinConstants.h"
#import "OIDCUserIdentifier.h"
#import "OIDCTelemetry.h"
#import "OIDCTelemetry+Internal.h"
#import "OIDCTelemetryUIEvent.h"
#import "OIDCTelemetryEventStrings.h"
#import "OIDCAuthenticationError+Internal.h"

#import "OIDCLogger.h"
#import "OIDCLogger+Internal.h"
#import "NSString+OIDCHelperMethods.h"
#import "OIDC_Internal.h"

/*! Fired at the start of a resource load in the webview. */
NSString* OIDCWebAuthDidStartLoadNotification = @"OIDCWebAuthDidStartLoadNotification";

/*! Fired when a resource finishes loading in the webview. */
NSString* OIDCWebAuthDidFinishLoadNotification = @"OIDCWebAuthDidFinishLoadNotification";

/*! Fired when web authentication fails due to reasons originating from the network. */
NSString* OIDCWebAuthDidFailNotification = @"OIDCWebAuthDidFailNotification";

/*! Fired when authentication finishes */
NSString* OIDCWebAuthDidCompleteNotification = @"OIDCWebAuthDidCompleteNotification";

NSString* OIDCWebAuthDidReceieveResponseFromBroker = @"OIDCWebAuthDidReceiveResponseFromBroker";

NSString* OIDCWebAuthWillSwitchToBrokerApp = @"OIDCWebAuthWillSwitchToBrokerApp";

// Private interface declaration
@interface OIDCWebAuthController () <OIDCWebAuthDelegate>
@end

// Implementation
@implementation OIDCWebAuthController

#pragma mark Shared Instance Methods

+ (id)alloc
{
    NSAssert( false, @"Cannot create instances of %@", NSStringFromClass( self ) );
    @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:[NSString stringWithFormat:@"Cannot create instances of %@", NSStringFromClass( self )] userInfo:nil];
    
    return nil;
}

+ (id)allocPrivate
{
    // [super alloc] calls to NSObject, and that calls [class allocWithZone:]
    return [super alloc];
}

+ (id)new
{
    return [self alloc];
}

- (id)copy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

- (id)mutableCopy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

#pragma mark - Initialization

- (id)init
{
    self = [super init];
    
    if ( self )
    {
        _completionLock = [[NSLock alloc] init];
    }
    
    return self;
}

+ (void)cancelCurrentWebAuthSession
{
    [[OIDCWebAuthController sharedInstance] webAuthDidCancel];
}

#pragma mark - Private Methods

- (void)dispatchCompletionBlock:(OIDCAuthenticationError *)error URL:(NSURL *)url
{
    // NOTE: It is possible that competition between a successful completion
    //       and the user cancelling the authentication dialog can
    //       occur causing this method to be called twice. The competition
    //       cannot be blocked at its root, and so this method must
    //       be resilient to this condition and should not generate
    //       two callbacks.
    [_completionLock lock];
    
    [OIDCURLProtocol unregisterProtocol];
    
    [self fillTelemetryUIEvent:_telemetryEvent];
    [[OIDCTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:_telemetryEvent];
    
    if ( _completionBlock )
    {
        void (^completionBlock)( OIDCAuthenticationError *, NSURL *) = _completionBlock;
        _completionBlock = nil;
        
        dispatch_async( dispatch_get_main_queue(), ^{
            completionBlock( error, url );
        });
    }
    
    [_completionLock unlock];
}

- (void)handlePKeyAuthChallenge:(NSString *)challengeUrl
{
    OIDC_LOG_INFO(@"Handling PKeyAuth Challenge", nil, nil);
    
    NSArray * parts = [challengeUrl componentsSeparatedByString:@"?"];
    NSString *qp = [parts objectAtIndex:1];
    NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
    NSString* value = [OIDCHelpers addClientVersionToURLString:[queryParamsMap valueForKey:@"SubmitUrl"]];
    
    NSArray * authorityParts = [value componentsSeparatedByString:@"?"];
    NSString *authority = [authorityParts objectAtIndex:0];
    
    OIDCAuthenticationError* adError = nil;
    NSString* authHeader = [OIDCPkeyAuthHelper createDeviceAuthResponse:authority
                                                        challengeData:queryParamsMap
                                                              context:_requestParams
                                                                error:&adError];
    if (!authHeader)
    {
        [self dispatchCompletionBlock:adError URL:nil];
        return;
    }
    
    NSMutableURLRequest* responseUrl = [[NSMutableURLRequest alloc]initWithURL:[NSURL URLWithString:value]];
    [OIDCURLProtocol addContext:_requestParams toRequest:responseUrl];
    
    [responseUrl setValue:kOIDCPKeyAuthHeaderVersion forHTTPHeaderField:kOIDCPKeyAuthHeader];
    [responseUrl setValue:authHeader forHTTPHeaderField:@"Authorization"];
    [_authenticationViewController loadRequest:responseUrl];
}

- (BOOL)endWebAuthenticationWithError:(OIDCAuthenticationError*) error
                                orURL:(NSURL*)endURL
{
    if (!_authenticationViewController)
    {
        return NO;
    }
    
    [_authenticationViewController stop:^{[self dispatchCompletionBlock:error URL:endURL];}];
    _authenticationViewController = nil;
    
    return YES;
}

- (void)onStartActivityIndicator:(id)sender
{
    (void)sender;
    
    if (_loading)
    {
        [_authenticationViewController startSpinner];
    }
    _spinnerTimer = nil;
}

- (void)stopSpinner
{
    if (!_loading)
    {
        return;
    }
    
    _loading = NO;
    if (_spinnerTimer)
    {
        [_spinnerTimer invalidate];
        _spinnerTimer = nil;
    }
    
    [_authenticationViewController stopSpinner];
}

#pragma mark - OIDCWebAuthDelegate

- (void)webAuthDidStartLoad:(NSURL*)url
{
    if (!_loading)
    {
        _loading = YES;
        if (_spinnerTimer)
        {
            [_spinnerTimer invalidate];
        }
        _spinnerTimer = [NSTimer scheduledTimerWithTimeInterval:2.0
                                                         target:self
                                                       selector:@selector(onStartActivityIndicator:)
                                                       userInfo:nil
                                                        repeats:NO];
        [_spinnerTimer setTolerance:0.3];
    }
    
    [[NSNotificationCenter defaultCenter] postNotificationName:OIDCWebAuthDidStartLoadNotification object:self userInfo:url ? @{ @"url" : url } : nil];
}

- (void)webAuthDidFinishLoad:(NSURL*)url
{
    OIDC_LOG_VERBOSE_F(@"-webAuthDidFinishLoad:", _requestParams.correlationId, @"host: %@", url.host);
    [self stopSpinner];
    [[NSNotificationCenter defaultCenter] postNotificationName:OIDCWebAuthDidFinishLoadNotification object:self userInfo:url ? @{ @"url" : url } : nil];
}

- (BOOL)webAuthShouldStartLoadRequest:(NSURLRequest *)request
{
    OIDC_LOG_VERBOSE_F(@"-webAuthShouldStartLoadRequest:", _requestParams.correlationId, @"host: %@", request.URL.host);
    if([OIDCNTLMHandler isChallengeCancelled])
    {
        _complete = YES;
        dispatch_async( dispatch_get_main_queue(), ^{[self webAuthDidCancel];});
        return NO;
    }
    
    NSString *requestURL = [request.URL absoluteString];

    if ([[requestURL lowercaseString] isEqualToString:@"about:blank"])
    {
        return NO;
    }
    
    if ([[[request.URL scheme] lowercaseString] isEqualToString:@"browser"])
    {
        _complete = YES;
        requestURL = [requestURL stringByReplacingOccurrencesOfString:@"browser://" withString:@"https://"];
        
#if TARGET_OS_IPHONE
        if (![OIDCAppExtensionUtil isExecutingInAppExtension])
        {
            dispatch_async( dispatch_get_main_queue(), ^{
                [self webAuthDidCancel];
            });
            
            dispatch_async( dispatch_get_main_queue(), ^{
                [OIDCAppExtensionUtil sharedApplicationOpenURL:[[NSURL alloc] initWithString:requestURL]];
            });
        }
        else
        {
            OIDC_LOG_ERROR(@"unable to redirect to browser from extension", OIDC_ERROR_SERVER_UNSUPPORTED_REQUEST, _requestParams.correlationId, nil);
        }
#else // !TARGET_OS_IPHONE
        [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:requestURL]];
#endif // TARGET_OS_IPHONE
        return NO;
    }
    
    // Stop at the end URL.
    if ([[requestURL lowercaseString] hasPrefix:[_endURL lowercaseString]] ||
        [[[request.URL scheme] lowercaseString] isEqualToString:@"oidcauth"])
    {
        // iOS generates a 102, Frame load interrupted error from stopLoading, so we set a flag
        // here to note that it was this code that halted the frame load in order that we can ignore
        // the error when we are notified later.
        _complete = YES;
        
#if OIDC_BROKER
        // If we're in the broker and we get a url with oidcauth that means we got an auth code back from the
        // client cert auth flow
        if ([[[request.URL scheme] lowercaseString] isEqualToString:@"oidcauth"])
        {
            [self webAuthDidCompleteWithURL:request.URL];
            return NO;
        }
#endif

        NSURL* url = request.URL;
        [self webAuthDidCompleteWithURL:url];
        
        // Tell the web view that this URL should not be loaded.
        return NO;
    }
    
    // check for pkeyauth challenge.
    if ([requestURL hasPrefix:kOIDCPKeyAuthUrn])
    {
        // We still continue onwards from a pkeyauth challenge after it's handled, so the web auth flow
        // is not complete yet.
        [self handlePKeyAuthChallenge:requestURL];
        return NO;
    }
    
    // redirecting to non-https url is not allowed
    if ([[[request.URL scheme] lowercaseString] isEqualToString:@"http"])
    {
        OIDC_LOG_ERROR(@"Server is redirecting to a non-https url", OIDC_ERROR_SERVER_NON_HTTPS_REDIRECT, nil, nil);
        _complete = YES;
        OIDCAuthenticationError* error = [OIDCAuthenticationError errorFromNonHttpsRedirect:_requestParams.correlationId];
        dispatch_async( dispatch_get_main_queue(), ^{[self endWebAuthenticationWithError:error orURL:nil];} );
        
        return NO;
    }
    
    if ([request isKindOfClass:[NSMutableURLRequest class]])
    {
        [OIDCURLProtocol addContext:_requestParams toRequest:(NSMutableURLRequest*)request];
    }
    
    return YES;
}

// The user cancelled authentication
- (void)webAuthDidCancel
{
    OIDC_LOG_INFO(@"-webAuthDidCancel", _requestParams.correlationId, nil);
    
    // Dispatch the completion block
    
    OIDCAuthenticationError* error = [OIDCAuthenticationError errorFromCancellation:_requestParams.correlationId];
    [self endWebAuthenticationWithError:error orURL:nil];
}

// Authentication completed at the end URL
- (void)webAuthDidCompleteWithURL:(NSURL *)endURL
{
    OIDC_LOG_INFO_F(@"-webAuthDidCompleteWithURL:", _requestParams.correlationId, @"%@", endURL);

    [self endWebAuthenticationWithError:nil orURL:endURL];
    [[NSNotificationCenter defaultCenter] postNotificationName:OIDCWebAuthDidCompleteNotification object:self userInfo:nil];
}

// Authentication failed somewhere
- (void)webAuthDidFailWithError:(NSError *)error
{
    // Ignore WebKitError 102 for OAuth 2.0 flow.
    if ([error.domain isEqualToString:@"WebKitErrorDomain"] && error.code == 102)
    {
        return;
    }
    
    // Prior to iOS 10 the WebView trapped out this error code and didn't pass it along to us
    // now we have to trap it out ourselves.
    if ([error.domain isEqualToString:NSCocoaErrorDomain] && error.code == NSUserCancelledError)
    {
        return;
    }
    
    // If we failed on an invalid URL check to see if it matches our end URL
    if ([error.domain isEqualToString:@"NSURLErrorDomain"] && (error.code == -1002 || error.code == -1003))
    {
        NSURL* url = [error.userInfo objectForKey:NSURLErrorFailingURLErrorKey];
        NSString* urlString = [url absoluteString];
        if ([[urlString lowercaseString] hasPrefix:_endURL.lowercaseString])
        {
            _complete = YES;
            [self webAuthDidCompleteWithURL:url];
            return;
        }
        
        // check for pkeyauth challenge.
        if ([urlString hasPrefix:kOIDCPKeyAuthUrn])
        {
            // We still continue onwards from a pkeyauth challenge after it's handled, so the web auth flow
            // is not complete yet.
            [self handlePKeyAuthChallenge:urlString];
            return;
        }
    }

    if (error)
    {
        OIDC_LOG_ERROR_F(@"-webAuthDidFailWithError:", error.code, _requestParams.correlationId, @"error: %@", error);

        [[NSNotificationCenter defaultCenter] postNotificationName:OIDCWebAuthDidFailNotification
                                                            object:self
                                                          userInfo:@{ @"error" : error}];
    }
    
    [self stopSpinner];
    
    if (NSURLErrorCancelled == error.code)
    {
        //This is a common error that webview generates and could be ignored.
        //See this thread for details: https://discussions.apple.com/thread/1727260
        return;
    }
    
    if([error.domain isEqual:@"WebKitErrorDomain"])
    {
        return;
    }
    
    // Ignore failures that are triggered after we have found the end URL
    if (_complete == YES)
    {
        //We expect to get an error here, as we intentionally fail to navigate to the final redirect URL.
        OIDC_LOG_VERBOSE(@"Expected error", _requestParams.correlationId, [error localizedDescription]);
        return;
    }
    
    // Dispatch the completion block
    __block OIDCAuthenticationError* adError = [OIDCAuthenticationError errorFromNSError:error errorDetails:error.localizedDescription correlationId:_requestParams.correlationId];
    
    dispatch_async(dispatch_get_main_queue(), ^{ [self endWebAuthenticationWithError:adError orURL:nil]; });
}

#if TARGET_OS_IPHONE
static OIDCAuthenticationResult* s_result = nil;

+ (OIDCAuthenticationResult*)responseFromInterruptedBrokerSession
{
    OIDCAuthenticationResult* result = s_result;
    s_result = nil;
    return result;
}
#endif // TARGET_OS_IPHONE

- (void)fillTelemetryUIEvent:(OIDCTelemetryUIEvent*)event
{
    if ([_requestParams identifier] && [[_requestParams identifier] isDisplayable] && ![NSString adIsStringNilOrBlank:[_requestParams identifier].userId])
    {
        [event setLoginHint:[_requestParams identifier].userId];
    }
}

@end

#pragma mark - Private Methods

@implementation OIDCWebAuthController (Internal)

+ (OIDCWebAuthController *)sharedInstance
{
    static OIDCWebAuthController *broker     = nil;
    static dispatch_once_t          predicate;
    
    dispatch_once( &predicate, ^{
        broker = [[self allocPrivate] init];
    });
    
    return broker;
}

- (BOOL)cancelCurrentWebAuthSessionWithError:(OIDCAuthenticationError*)error
{
    OIDC_LOG_ERROR_F(@"Application is cancelling current web auth session.", error.code, _requestParams.correlationId, @"error = %@", error);
    return [self endWebAuthenticationWithError:error orURL:nil];
}

-(NSURL*) addToURL: (NSURL*) url
     correlationId: (NSUUID*) correlationId
{
    return [NSURL URLWithString:[NSString stringWithFormat:@"%@&%@=%@",
                                 [url absoluteString], OAUTH2_CORRELATION_ID_REQUEST_VALUE, [correlationId UUIDString]]];
}

- (void)start:(NSURL *)startURL
          end:(NSURL *)endURL
  refreshCred:(NSString *)refreshCred
#if TARGET_OS_IPHONE
       parent:(UIViewController *)parent
   fullScreen:(BOOL)fullScreen
#endif
      webView:(WebViewType *)webView
      context:(OIDCRequestParameters*)requestParams
   completion:(OIDCBrokerCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(startURL);
    THROW_ON_NIL_ARGUMENT(endURL);
    THROW_ON_NIL_ARGUMENT(requestParams.correlationId);
    THROW_ON_NIL_ARGUMENT(completionBlock);
    
    // If we're not on the main thread when trying to kick up the UI then
    // dispatch over to the main thread.
    if (![NSThread isMainThread])
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self start:startURL
                    end:endURL
            refreshCred:refreshCred
#if TARGET_OS_IPHONE
                 parent:parent
             fullScreen:fullScreen
#endif
                webView:webView
                context:requestParams
             completion:completionBlock];
        });
        return;
    }

    [[OIDCTelemetry sharedInstance] startEvent:requestParams.telemetryRequestId eventName:OIDC_TELEMETRY_EVENT_UI_EVENT];
    _telemetryEvent = [[OIDCTelemetryUIEvent alloc] initWithName:OIDC_TELEMETRY_EVENT_UI_EVENT
                                                                 context:_requestParams];
    
    startURL = [[OIDCAuthorityValidation sharedInstance] networkUrlForAuthority:startURL context:requestParams];
    startURL = [self addToURL:startURL correlationId:requestParams.correlationId];//Append the correlation id
    _endURL = [endURL absoluteString];
    _complete = NO;
    
    _requestParams = requestParams;
    
    // Save the completion block
    _completionBlock = [completionBlock copy];
    OIDCAuthenticationError* error = nil;
    
    [OIDCURLProtocol registerProtocol:[endURL absoluteString] telemetryEvent:_telemetryEvent];
    
    if(![NSString adIsStringNilOrBlank:refreshCred])
    {
        [OIDCCustomHeaderHandler addCustomHeaderValue:refreshCred
                                       forHeaderKey:@"x-ms-RefreshTokenCredential"
                                       forSingleUse:YES];
    }
    
    _authenticationViewController = [[OIDCAuthenticationViewController alloc] init];
    [_authenticationViewController setDelegate:self];
    [_authenticationViewController setWebView:webView];
#if TARGET_OS_IPHONE
    [_authenticationViewController setParentController:parent];
    [_authenticationViewController setFullScreen:fullScreen];
#endif
    
    if (![_authenticationViewController loadView:&error])
    {
        _completionBlock(error, nil);
    }
    
    NSMutableURLRequest* request = [[NSMutableURLRequest alloc] initWithURL:[OIDCHelpers addClientVersionToURL:startURL]];

    [OIDCURLProtocol addContext:_requestParams toRequest:request];

    [_authenticationViewController startRequest:request];
}

#if TARGET_OS_IPHONE
+ (void)setInterruptedBrokerResult:(OIDCAuthenticationResult*)result
{
    s_result = result;
}
#endif // TARGET_OS_IPHONE

- (OIDCAuthenticationViewController*)viewController
{
    return _authenticationViewController;
}

@end
