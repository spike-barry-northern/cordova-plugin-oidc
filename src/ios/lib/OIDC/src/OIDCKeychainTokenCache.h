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

@class OIDCKeyChainHelper;
@class OIDCTokenCacheItem;
@class OIDCAuthenticationError;

@interface OIDCKeychainTokenCache : NSObject

@property (readonly) NSString* __nonnull sharedGroup;

/*!
     The name of the keychain group to be used by default when creating an OIDCAuthenticationContext,
     the default value is com.cordovaplugin.oidccache.
 */
+ (nullable NSString*)defaultKeychainGroup;

/*!
     Set the default keychain sharing group to use with OIDC. If set to 'nil' the main bundle's
     identifier will be used instead. Any keychain sharing group other then the main bundle's identifier
     will require a keychain sharing group entitlement.
 
     See apple's documentation for keychain groups: such groups require certain
     entitlements to be set by the applications. Additionally, access to the items in this group
     is only given to the applications from the same vendor. If this property is not set, the behavior
     will depend on the values in the entitlements file (if such exists) and may not result in token
     sharing. The property has no effect if other cache mechanisms are used (non-keychain).

 
     NOTE: Once an authentication context has been created with the default keychain
     group, or +[OIDCKeychainTokenCache defaultKeychainCache] has been called then
     this value cannot be changed. Doing so will throw an exception.
 */
+ (void)setDefaultKeychainGroup:(nullable NSString*)keychainGroup;

/*!
    @return A singleton instance of the OIDCKeychainTokenCache for the default keychain group.
 */
+ (nonnull OIDCKeychainTokenCache*)defaultKeychainCache;

/*!
    @return An instance of OIDCKeychainTokenCache for the given group, or the defaultKeychainCache
            singleton if the default keychain group is passed in.
 */
+ (nonnull OIDCKeychainTokenCache*)keychainCacheForGroup:(nullable NSString*)group;

/* Initializes the token cache store with default shared group value.
 */
- (nonnull instancetype)init;

/*! Initializes the token cache store.
 @param sharedGroup Optional. If the application needs to share the cached tokens
 with other applications from the same vendor, the app will need to specify the 
 shared group here and add the necessary entitlements to the application.
 See Apple's keychain services documentation for details. */
- (nullable instancetype)initWithGroup:(nullable NSString *)sharedGroup;

/*! Return a copy of all items. The array will contain OIDCTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (nullable NSArray<OIDCTokenCacheItem *> *)allItems:(OIDCAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (BOOL)removeItem:(nonnull OIDCTokenCacheItem *)item
             error:(OIDCAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (BOOL)removeAllForClientId:(NSString * __nonnull)clientId
                       error:(OIDCAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (BOOL)removeAllForUserId:(NSString * __nonnull)userId
                  clientId:(NSString * __nonnull)clientId
                     error:(OIDCAuthenticationError * __nullable __autoreleasing * __nullable)error;

@end
