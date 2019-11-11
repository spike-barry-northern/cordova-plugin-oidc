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

#import <objc/runtime.h>
#import "OIDC_Internal.h"
#import "NSDictionary+OIDCExtensions.h"

#import "OIDCBrokerHelper.h"
#import "OIDCBrokerNotificationManager.h"
#import "OIDCOAuth2Constants.h"
#import "OIDCWebAuthController+Internal.h"
#import "OIDCAppExtensionUtil.h"

typedef BOOL (*applicationHandleOpenURLPtr)(id, SEL, UIApplication*, NSURL*);
IMP __original_ApplicationHandleOpenURL = NULL;

typedef BOOL (*applicationOpenURLPtr)(id, SEL, UIApplication*, NSURL*, NSString*, id);
IMP __oidc_original_ApplicationOpenURL = NULL;

BOOL __oidc_swizzle_ApplicationOpenURL(id self, SEL _cmd, UIApplication* application, NSURL* url, NSString* sourceApplication, id annotation)
{
    if ([OIDCAuthenticationContext isResponseFromBroker:sourceApplication response:url])
    {
        // Attempt to handle response from broker
        BOOL result = [OIDCAuthenticationContext handleBrokerResponse:url];

        if (result)
        {
            // Successfully handled broker response
            return YES;
        }
    }

    // Fallback to original delegate if defined
    if (__oidc_original_ApplicationOpenURL)
    {
        return ((applicationOpenURLPtr)__oidc_original_ApplicationOpenURL)(self, _cmd, application, url, sourceApplication, annotation);
    }
    else if (__original_ApplicationHandleOpenURL)
    {
        return ((applicationHandleOpenURLPtr)__original_ApplicationHandleOpenURL)(self, @selector(application:handleOpenURL:), application, url);
    }
    else
    {
        return NO;
    }
}

typedef BOOL (*applicationOpenURLiOS9Ptr)(id, SEL, UIApplication*, NSURL*, NSDictionary<NSString*, id>*);
IMP __oidc_original_ApplicationOpenURLiOS9 = NULL;

BOOL __oidc_swizzle_ApplicationOpenURLiOS9(id self, SEL _cmd, UIApplication* application, NSURL* url, NSDictionary<NSString*, id>* options)
{
    NSString* sourceApplication = [options objectForKey:UIApplicationOpenURLOptionsSourceApplicationKey];

    if ([OIDCAuthenticationContext isResponseFromBroker:sourceApplication response:url])
    {
        // Attempt to handle response from broker
        BOOL result = [OIDCAuthenticationContext handleBrokerResponse:url];

        if (result)
        {
            // Successfully handled broker response
            return YES;
        }

    }

    // Fallback to original delegate if defined
    if (__oidc_original_ApplicationOpenURLiOS9)
    {
        return ((applicationOpenURLiOS9Ptr)__oidc_original_ApplicationOpenURLiOS9)(self, _cmd, application, url, options);
    }
    else if (__original_ApplicationHandleOpenURL)
    {
        return ((applicationHandleOpenURLPtr)__original_ApplicationHandleOpenURL)(self, @selector(application:handleOpenURL:), application, url);
    }
    else
    {
        return NO;
    }
}

@implementation OIDCBrokerHelper

// If we are in the broker, do not intercept openURL calls
#if !OIDC_BROKER
+ (void)load
{
    if ([OIDCAppExtensionUtil isExecutingInAppExtension])
    {
        // Avoid any setup in application extension hosts
        return;
    }

    __block __weak id observer = nil;
    
    observer =
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil
                                                       queue:nil
                                                  usingBlock:^(NSNotification* notification)
     {
         (void)notification;
         // We don't want to swizzle multiple times so remove the observer
         [[NSNotificationCenter defaultCenter] removeObserver:observer name:UIApplicationDidFinishLaunchingNotification object:nil];
         
         SEL sel = @selector(application:openURL:sourceApplication:annotation:);
         SEL seliOS9 = @selector(application:openURL:options:);
         SEL handleOpenURLSel = @selector(application:handleOpenURL:);
         
         // Dig out the app delegate (if there is one)
         __strong id appDelegate = [[OIDCAppExtensionUtil sharedApplication] delegate];
         
         // There's not much we can do if there's no app delegate and there might be scenarios where
         // that is valid...
         if (appDelegate == nil)
             return;
         
         // Support applications which implement handleOpenURL to handle URL requests.
         // An openURL method will be added to the application's delegate, but the request will be
         // forwarded to the application's handleOpenURL: method once handled by OIDC.
         if ([appDelegate respondsToSelector:handleOpenURLSel])
         {
             Method m = class_getInstanceMethod([appDelegate class], handleOpenURLSel);
             __original_ApplicationHandleOpenURL = method_getImplementation(m);
         }
         
         BOOL iOS9OrGreater = [[[UIDevice currentDevice] systemVersion] intValue] >= 9;
         
         if ([appDelegate respondsToSelector:seliOS9] && iOS9OrGreater)
         {
             Method m = class_getInstanceMethod([appDelegate class], seliOS9);
             __oidc_original_ApplicationOpenURLiOS9 = method_getImplementation(m);
             method_setImplementation(m, (IMP)__oidc_swizzle_ApplicationOpenURLiOS9);
         }
         else if ([appDelegate respondsToSelector:sel])
         {
             Method m = class_getInstanceMethod([appDelegate class], sel);
             __oidc_original_ApplicationOpenURL = method_getImplementation(m);
             method_setImplementation(m, (IMP)__oidc_swizzle_ApplicationOpenURL);
         }
         else if (iOS9OrGreater)
         {
             NSString* typeEncoding = [NSString stringWithFormat:@"%s%s%s%s%s%s", @encode(BOOL), @encode(id), @encode(SEL), @encode(UIApplication*), @encode(NSURL*), @encode(NSDictionary<NSString*, id>*)];
             class_addMethod([appDelegate class], seliOS9, (IMP)__oidc_swizzle_ApplicationOpenURLiOS9, [typeEncoding UTF8String]);
             
             // UIApplication caches whether or not the delegate responds to certain selectors. Clearing out the delegate and resetting it gaurantees that gets updated
             [[OIDCAppExtensionUtil sharedApplication] setDelegate:nil];
             // UIApplication employs dark magic to assume ownership of the app delegate when it gets the app delegate at launch, it won't do that for setDelegate calls so we
             // have to add a retain here to make sure it doesn't turn into a zombie
             [[OIDCAppExtensionUtil sharedApplication] setDelegate:(__bridge id)CFRetain((__bridge CFTypeRef)appDelegate)];
         }
         else
         {
             NSString* typeEncoding = [NSString stringWithFormat:@"%s%s%s%s%s%s%s", @encode(BOOL), @encode(id), @encode(SEL), @encode(UIApplication*), @encode(NSURL*), @encode(NSString*), @encode(id)];
             class_addMethod([appDelegate class], sel, (IMP)__oidc_swizzle_ApplicationOpenURL, [typeEncoding UTF8String]);
             
             // UIApplication caches whether or not the delegate responds to certain selectors. Clearing out the delegate and resetting it gaurantees that gets updated
             [[OIDCAppExtensionUtil sharedApplication] setDelegate:nil];
             // UIApplication employs dark magic to assume ownership of the app delegate when it gets the app delegate at launch, it won't do that for setDelegate calls so we
             // have to add a retain here to make sure it doesn't turn into a zombie
             [[OIDCAppExtensionUtil sharedApplication] setDelegate:(__bridge id)CFRetain((__bridge CFTypeRef)appDelegate)];
         }
     }];
}
#endif

+ (BOOL)canUseBroker
{
    if (![OIDCAppExtensionUtil isExecutingInAppExtension])
    {
        // Verify broker app url can be opened
        return [[OIDCAppExtensionUtil sharedApplication] canOpenURL:[[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://broker", OIDC_BROKER_SCHEME]]];
    }
    else
    {
        // Cannot perform app switching from application extension hosts
        return NO;
    }
}

+ (void)invokeBroker:(NSURL *)brokerURL
   completionHandler:(OIDCAuthenticationCallback)completion
{
    if ([OIDCAppExtensionUtil isExecutingInAppExtension])
    {
        // Ignore invocation in application extension hosts
        OIDCAuthenticationError* error = [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_TOKENBROKER_NOT_SUPPORTED_IN_EXTENSION
                                                                              protocolCode:nil
                                                                              errorDetails:@"Calling to broker is not supported in app extensions"
                                                                             correlationId:nil];
        completion([OIDCAuthenticationResult resultFromError:error]);
        return;
    }
    
    [[OIDCBrokerNotificationManager sharedInstance] enableNotifications:completion];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:OIDCWebAuthWillSwitchToBrokerApp object:nil];
        
        [OIDCAppExtensionUtil sharedApplicationOpenURL:brokerURL];
    });
}

+ (void)saveToPasteBoard:(NSURL*) url
{
    UIPasteboard *appPasteBoard = [UIPasteboard pasteboardWithName:@"WPJ"
                                                            create:YES];
    appPasteBoard.persistent = YES;
    url = [NSURL URLWithString:[NSString stringWithFormat:@"%@&%@=%@", url.absoluteString, @"sourceApplication",[[NSBundle mainBundle] bundleIdentifier]]];
    [appPasteBoard setURL:url];
}

+ (void)promptBrokerInstall:(NSURL *)redirectURL
              brokerRequest:(NSURL *)brokerRequest
          completionHandler:(OIDCAuthenticationCallback)completion
{
    if ([OIDCAppExtensionUtil isExecutingInAppExtension])
    {
        // Ignore invocation in application extension hosts
        completion(nil);
        return;
    }
    
    NSString* query = [redirectURL query];
    NSDictionary* queryParams = [NSDictionary adURLFormDecode:query];
    NSString* appURLString = [queryParams objectForKey:@"app_link"];
    __block NSURL* appURL = [NSURL URLWithString:appURLString];
                        
    [[OIDCBrokerNotificationManager sharedInstance] enableNotifications:completion];
    [self saveToPasteBoard:brokerRequest];
    dispatch_async(dispatch_get_main_queue(), ^{
        [OIDCAppExtensionUtil sharedApplicationOpenURL:appURL];
    });
}

+ (OIDCAuthenticationCallback)copyAndClearCompletionBlock
{
    return [[OIDCBrokerNotificationManager sharedInstance] copyAndClearCallback];
}

@end
