/*******************************************************************************
 * Copyright (c) Microsoft Open Technologies, Inc.
 * All Rights Reserved
 * See License in the project root for license information.
 ******************************************************************************/

#import <Foundation/Foundation.h>
#import "OIDC.h"

// Implements helper functionality for Cordova OIDC Plugin.
@interface CordovaOidcUtils : NSObject

// Populates dictonary from OIDCAuthenticationResult class instance.
+ (NSMutableDictionary *)OIDCAuthenticationResultToDictionary:(OIDCAuthenticationResult *)obj;

// Populates dictonary from OIDCUserInformation class instance.
+ (id)OIDCUserInformationToDictionary:(OIDCUserInformation *)obj;

// Populates dictonary from OIDCTokenCacheStoreItem class instance.
+ (NSMutableDictionary *)OIDCAuthenticationErrorToDictionary:(OIDCAuthenticationError *)obj;

// Populates dictonary from OIDCTokenCacheStoreItem class instance.
+ (NSMutableDictionary *)OIDCTokenCacheStoreItemToDictionary:(OIDCTokenCacheItem *)obj;

// Retrieves user name from Token Cache Store.
+ (NSString *)mapUserIdToUserName:(OIDCAuthenticationContext *)authContext
                           userId:(NSString *)userId;
@end
