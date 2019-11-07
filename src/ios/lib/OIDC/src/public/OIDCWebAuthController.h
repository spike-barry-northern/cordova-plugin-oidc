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

@class OIDCAuthenticationError;
@class OIDCAuthenticationViewController;
@class OIDCTelemetryUIEvent;
@class OIDCRequestParameters;

#import "OIDCAuthenticationContext.h"

/*! Fired at the start of a resource load in the webview. The URL of the load, if available, will be in the @"url" key in the userInfo dictionary */
extern NSString* OIDCWebAuthDidStartLoadNotification;

/*! Fired when a resource finishes loading in the webview. */
extern NSString* OIDCWebAuthDidFinishLoadNotification;

/*! Fired when web authentication fails due to reasons originating from the network. Look at the @"error" key in the userInfo dictionary for more details.*/
extern NSString* OIDCWebAuthDidFailNotification;

/*! Fired when authentication finishes */
extern NSString* OIDCWebAuthDidCompleteNotification;

/*! Fired before OIDC invokes the broker app */
extern NSString* OIDCWebAuthWillSwitchToBrokerApp;

/*! Fired when the application receives a response from the broker. Look at the @"response"
    key in the userInfo dictionary for the broker response */
extern NSString* OIDCWebAuthDidReceieveResponseFromBroker;

@interface OIDCWebAuthController : NSObject
{
    OIDCAuthenticationViewController * _authenticationViewController;
    
    NSLock * _completionLock;
    NSString * _endURL;
    
    BOOL _loading;
    // Used for managing the activity spinner
    NSTimer* _spinnerTimer;
    
    BOOL _complete;
    
    OIDCRequestParameters* _requestParams;
    OIDCTelemetryUIEvent* _telemetryEvent;
    
    void (^_completionBlock)( OIDCAuthenticationError *, NSURL *);
}

//Cancel the web authentication session which might be happening right now
//Note that it only works if there's an active web authentication session going on
+ (void)cancelCurrentWebAuthSession;

#if TARGET_OS_IPHONE
/*!
 If the application was terminated between OIDC calling out to the broker app and
 receiving a response, then the request can't be continued in a normal fashion. An
 application can use this API to retrieve a response that was received from the
 broker but we no longer had an active completion block to hand it to.
 */
+ (OIDCAuthenticationResult *)responseFromInterruptedBrokerSession;
#endif

@end
