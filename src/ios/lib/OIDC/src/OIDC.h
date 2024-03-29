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

#import <Foundation/Foundation.h>

#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#endif

//! Project version number for OIDCFramework.
FOUNDATION_EXPORT double OIDCFrameworkVersionNumber;

//! Project version string for OIDCFramework.
FOUNDATION_EXPORT const unsigned char OIDCFrameworkVersionString[];

#if TARGET_OS_IPHONE
//iOS:
typedef WKWebView WebViewType;
#else
//OS X:
typedef WebView   WebViewType;
#endif

@class OIDCAuthenticationResult;

/*! The completion block declaration. */
typedef void(^OIDCAuthenticationCallback)(OIDCAuthenticationResult* result);

#import "OIDCAuthenticationContext.h"
#import "OIDCAuthenticationError.h"
#import "OIDCAuthenticationParameters.h"
#import "OIDCAuthenticationResult.h"
#import "OIDCAuthenticationSettings.h"
#import "OIDCErrorCodes.h"
#import "OIDCLogger.h"
#import "OIDCTokenCacheItem.h"
#import "OIDCUserIdentifier.h"
#import "OIDCUserInformation.h"
#import "OIDCWebAuthController.h"
#import "OIDCTelemetry.h"

#if TARGET_OS_IPHONE
#import "OIDCKeychainTokenCache.h"
#else
#import "OIDCTokenCache.h"
#endif

