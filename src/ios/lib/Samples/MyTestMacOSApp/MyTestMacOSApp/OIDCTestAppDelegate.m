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

#import "OIDCTestAppDelegate.h"
#import "OIDCTestAppSettings.h"
#import "OIDC_Internal.h"
#import "OIDCTokenCache.h"
#import "OIDCTestAppAcquireTokenWindowController.h"
#import "OIDCTestAppCacheWindowController.h"
#import "OIDCWebAuthController.h"

// These are not public APIs, however the test app is pulling
// in things that can't be done with public APIs and shouldn't
// be done in a normal app.
@interface OIDCTokenCache (Internal)
- (BOOL)addOrUpdateItem:(OIDCTokenCacheItem *)item
                  error:(OIDCAuthenticationError * __autoreleasing *)error;
@end


@implementation OIDCTestAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    [self showAcquireToken:nil];
}

- (IBAction)showAcquireToken:(id)sender
{
    [OIDCTestAppAcquireTokenWindowController showWindow];
}

- (IBAction)showConsoleLog:(id)sender
{
    
}

- (IBAction)showCacheViewer:(id)sender
{
    [OIDCTestAppCacheWindowController showWindow];
}

- (IBAction)loadCacheFromFile:(id)sender
{
    
}

- (IBAction)writeCacheToFile:(id)sender
{
    
}

- (IBAction)cancelCurrentSession:(id)sender
{
    [OIDCWebAuthController cancelCurrentWebAuthSession];
}

@end
