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

#import "OIDCWorkPlaceJoinConstants.h"

//NSString *const OIDC_TELEMETRY_EVENT_API_EVENT              = @"CordovaPlugin.OIDC.api_event";

NSString* const kOIDCDefaultSharedGroup                = @"com.cordovaplugin.workplacejoin";
NSString* const kOIDCPrivateKeyIdentifier               = @"com.cordovaplugin.workplacejoin.privatekey\0";
NSString* const kOIDCPublicKeyIdentifier                = @"com.cordovaplugin.workplacejoin.publickey\0";
NSString* const kOIDCUpnIdentifier                      = @"com.cordovaplugin.workplacejoin.registeredUserPrincipalName";
NSString* const kOIDCApplicationIdentifierPrefix        = @"applicationIdentifierPrefix";
NSString* const kOIDCOauthRedirectUri                  = @"ms-app://windows.immersivecontrolpanel";
NSString* const kOIDCProtectionSpaceDistinguishedName   = @"MS-Organization-Access";
//
//#pragma mark Error strings
NSString* const kOIDCErrorDomain                        = @"com.cordovaplugin.workplacejoin.errordomain";
NSString* const kOIDCAlreadyWorkplaceJoined             = @"This device is already workplace joined";
NSString* const kOIDCInvalidUPN                         = @"Invalid UPN";
NSString* const kOIDCUnabletoWriteToSharedKeychain      = @"Unable to write to shared access group: %@";
NSString* const kOIDCUnabletoReadFromSharedKeychain     = @"Unable to read from shared access group: %@ with error code: %@";
NSString* const kOIDCDuplicateCertificateEntry          = @"Duplicate workplace certificate entry";
NSString* const kOIDCCertificateInstallFailure          = @"Install workplace certificate failure";
NSString* const kOIDCCertificateDeleteFailure           = @"Delete workplace certificate failure";
NSString* const kOIDCUpnMismatchOnJoin                  = @"Original upn: %@ does not match the one we recieved from DRS: %@";
NSString* const kOIDCWwwAuthenticateHeader              = @"WWW-Authenticate";
NSString* const kOIDCPKeyAuthUrn                        = @"urn:http-auth:PKeyAuth?";
NSString* const kOIDCPKeyAuthHeader                     = @"x-ms-PkeyAuth";
NSString* const kOIDCPKeyAuthHeaderVersion              = @"1.0";
NSString* const kOIDCPKeyAuthName                       = @"PKeyAuth";

#pragma mark general
NSString* const kOIDCOID                                = @"1.2.840.113556.1.5.284.2";


