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

#import <Security/Security.h>
#import <SecurityInterface/SFChooseIdentityPanel.h>

#import "OIDCClientCertAuthHandler.h"
#import "OIDCWorkPlaceJoinUtil.h"
#import "OIDCRegistrationInformation.h"
#import "OIDCWorkPlaceJoinConstants.h"
#import "OIDCWebAuthController+Internal.h"
#import "OIDCAuthenticationViewController.h"

@interface OIDCCertificateChooserHelper : NSObject 

+ (SecIdentityRef)showCertSelectionSheet:(NSArray *)identities
                                    host:(NSString *)host
                           correlationId:(NSUUID *)correlationId;

@end


@implementation OIDCClientCertAuthHandler

+ (void)load
{
    [OIDCURLProtocol registerHandler:self authMethod:NSURLAuthenticationMethodClientCertificate];
}

+ (void)resetHandler
{
}


+ (BOOL)isWPJChallenge:(NSArray *)distinguishedNames
{
    
    for (NSData *distinguishedName in distinguishedNames)
    {
        NSString *distinguishedNameString = [[[NSString alloc] initWithData:distinguishedName encoding:NSISOLatin1StringEncoding] lowercaseString];
        if ([distinguishedNameString containsString:[kOIDCProtectionSpaceDistinguishedName lowercaseString]])
        {
            return YES;
        }
    }
    
    return NO;
}

+ (BOOL)handleWPJChallenge:(NSURLAuthenticationChallenge *)challenge
                  protocol:(OIDCURLProtocol *)protocol
         completionHandler:(ChallengeCompletionHandler)completionHandler
{
    OIDCAuthenticationError *adError = nil;
    OIDCRegistrationInformation *info = [OIDCWorkPlaceJoinUtil getRegistrationInformation:protocol.context error:&adError];
    if (!info || ![info isWorkPlaceJoined])
    {
        OIDC_LOG_INFO_F(@"Device is not workplace joined.", protocol.context.correlationId, @"host: %@", challenge.protectionSpace.host);
        
        // In other cert auth cases we send Cancel to ensure that we continue to get
        // auth challenges, however when we do that with WPJ we don't get the subsequent
        // enroll dialog *after* the failed clientTLS challenge.
        //
        // Using DefaultHandling will result in the OS not handing back client TLS
        // challenges for another ~60 seconds, behavior that looks broken in the
        // user CBA case, but here is masked by the user having to enroll their
        // device.
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return YES;
    }
    
    OIDC_LOG_INFO_F(@"Responding to WPJ cert challenge", protocol.context.correlationId, @"host: %@", challenge.protectionSpace.host);
    
    NSURLCredential *creds = [NSURLCredential credentialWithIdentity:info.securityIdentity
                                                        certificates:@[(__bridge id)info.certificate]
                                                         persistence:NSURLCredentialPersistenceNone];
    
    completionHandler(NSURLSessionAuthChallengeUseCredential, creds);
    
    return YES;
}

+ (SecIdentityRef)promptUserForIdentity:(NSArray *)issuers
                                   host:(NSString *)host
                          correlationId:(NSUUID *)correlationId
{
    NSMutableDictionary *query =
    [@{
      (id)kSecClass : (id)kSecClassIdentity,
      (id)kSecMatchLimit : (id)kSecMatchLimitAll,
      } mutableCopy];
    
    if (issuers.count > 0)
    {
        [query setObject:issuers forKey:(id)kSecMatchIssuers];
    }
    
    CFTypeRef result = NULL;
    
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound)
    {
        OIDC_LOG_INFO(@"No certificate found matching challenge", correlationId, nil);
        return nil;
    }
    else if (status != errSecSuccess)
    {
        OIDC_LOG_ERROR(([NSString stringWithFormat:@"Failed to find identity matching issuers with %d error.", status]), status, correlationId, nil);
        return nil;
    }
    
    return [OIDCCertificateChooserHelper showCertSelectionSheet:(__bridge NSArray *)result host:host correlationId:correlationId];
}


+ (BOOL)handleChallenge:(NSURLAuthenticationChallenge *)challenge
                session:(NSURLSession *)session
                   task:(NSURLSessionTask *)task
               protocol:(OIDCURLProtocol *)protocol
      completionHandler:(ChallengeCompletionHandler)completionHandler;
{
#pragma unused(session)
#pragma unused(task)
    
    NSUUID *correlationId = protocol.context.correlationId;
    NSString *host = challenge.protectionSpace.host;
    OIDC_LOG_INFO_F(@"Attempting to handle client certificate challenge", correlationId, @"host: %@", host);
    
    // See if this is a challenge for the WPJ cert.
    NSArray<NSData*> *distinguishedNames = challenge.protectionSpace.distinguishedNames;
    if ([self isWPJChallenge:distinguishedNames])
    {
        return [self handleWPJChallenge:challenge protocol:protocol completionHandler:completionHandler];
    }
    
    // Otherwise check if a preferred identity is set for this host
    SecIdentityRef identity = SecIdentityCopyPreferred((CFStringRef)host, NULL, (CFArrayRef)distinguishedNames);
    if (identity != NULL)
    {
        OIDC_LOG_INFO(@"Using preferred identity", correlationId, nil);
    }
    else
    {
        // If not prompt the user to select an identity
        identity = [self promptUserForIdentity:distinguishedNames host:host correlationId:correlationId];
        if (identity == NULL)
        {
            OIDC_LOG_INFO(@"No identity returned from cert chooser", correlationId, nil);
            // If no identity comes back then we can't handle the request
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            return YES;
        }
        
        // Adding a retain count to match the retain count from SecIdentityCopyPreferred
        CFRetain(identity);
        OIDC_LOG_INFO(@"Using user selected certificate", correlationId, nil);
    }
    
    SecCertificateRef cert = NULL;
    OSStatus status = SecIdentityCopyCertificate(identity, &cert);
    if (status != errSecSuccess)
    {
        CFRelease(identity);
        OIDC_LOG_ERROR(@"Failed to copy certificate from identity", OIDC_ERROR_UNEXPECTED, correlationId, nil);
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return YES;
    }
    
    OIDC_LOG_INFO(@"Responding to cert auth challenge with certicate", correlationId, nil);
    NSURLCredential *credential = [[NSURLCredential alloc] initWithIdentity:identity certificates:@[(__bridge id)cert] persistence:NSURLCredentialPersistenceNone];
    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    CFRelease(cert);
    CFRelease(identity);
    return YES;
}

@end

@implementation OIDCCertificateChooserHelper
{
    NSUUID *_correlationId;
    NSWindow *_window;
    SFChooseIdentityPanel *_panel;
    dispatch_semaphore_t _sem;
    NSInteger _returnCode;
}

+ (SecIdentityRef)showCertSelectionSheet:(NSArray *)identities
                                    host:(NSString *)host
                           correlationId:(NSUUID *)correlationId
{
    NSString *localizedTemplate = NSLocalizedString(@"Please select a certificate for %1", @"certificate dialog selection prompt \"%1\" will be replaced with the URL host");
    NSString *message = [localizedTemplate stringByReplacingOccurrencesOfString:@"%1" withString:host];
    
    OIDCCertificateChooserHelper *helper = [OIDCCertificateChooserHelper new];
    helper->_correlationId = correlationId;
    return [helper showCertSelectionSheet:identities message:message];
}

- (void)beginSheet:(NSArray *)identities
           message:(NSString *)message
{
    _window = [[[OIDCWebAuthController sharedInstance] viewController] webviewWindow];
    _panel = [SFChooseIdentityPanel new];
    [_panel setAlternateButtonTitle:NSLocalizedString(@"Cancel", "Cancel button on cert selection sheet")];
    [_panel beginSheetForWindow:_window
                  modalDelegate:self
                 didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)
                    contextInfo:NULL
                     identities:identities
                        message:message];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(webAuthDidFail:) name:OIDCWebAuthDidFailNotification object:nil];
}

- (SecIdentityRef)showCertSelectionSheet:(NSArray *)identities
                                 message:(NSString *)message
{
    _sem = dispatch_semaphore_create(0);
    OIDC_LOG_INFO(@"Displaying Cert Selection Sheet", _correlationId, nil);
    
    // This code should always be called from a network thread.
    assert(![NSThread isMainThread]);
    
    dispatch_async(dispatch_get_main_queue(), ^{ [self beginSheet:identities message:message]; });
    dispatch_semaphore_wait(_sem, DISPATCH_TIME_FOREVER);
    
    if (_returnCode != NSModalResponseOK)
    {
        OIDC_LOG_INFO(@"no certificate selected", _correlationId, nil);
        return NULL;
    }
    
    SecIdentityRef identity = _panel.identity;
    _panel = nil;
    return identity;
}

- (void)sheetDidEnd:(NSWindow *)window
         returnCode:(NSInteger)returnCode
        contextInfo:(void *)contextInfo
{
    (void)window;
    (void)contextInfo;
    
    _returnCode = returnCode;
    _window = nil;
    [[NSNotificationCenter defaultCenter] removeObserver:self name:OIDCWebAuthDidFailNotification object:nil];
    dispatch_semaphore_signal(_sem);
}

- (void)webAuthDidFail:(NSNotification *)aNotification
{
    (void)aNotification;
    
    if (!_panel || !_window)
    {
        return;
    }
    
    // If web auth fails while the sheet is up that usually means the connection timed out, tear
    // down the cert selection sheet.
    
    OIDC_LOG_INFO(@"Aborting cert selection due to web auth failure", _correlationId, nil);
    NSArray *sheets = _window.sheets;
    if (sheets.count < 1)
    {
        OIDC_LOG_ERROR(@"Unable to find sheet to dismiss for client cert auth handler", OIDC_ERROR_UNEXPECTED, _correlationId, nil);
        return;
    }
    // It turns out the SFChooseIdentityPanel is not the real sheet that gets displayed, so telling the window to end it
    // results in nothing happening. If I instead pull out the sheet from the window itself I can tell the window to end
    // that and it works.
    [_window endSheet:sheets[0] returnCode:NSModalResponseCancel];
}

@end
