/*******************************************************************************
 * Copyright (c) Microsoft Open Technologies, Inc.
 * All Rights Reserved
 * See License in the project root for license information.
 ******************************************************************************/

#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>

#import "OIDCAuthenticationContext.h"

// Implements Apache Cordova plugin for Microsoft Azure OIDC
@interface CordovaOidcPlugin : CDVPlugin

// AuthenticationContext methods
- (void)createAsync:(CDVInvokedUrlCommand *)command;
- (void)acquireTokenAsync:(CDVInvokedUrlCommand *)command;
- (void)acquireTokenSilentAsync:(CDVInvokedUrlCommand *)command;

// TokenCache methods
- (void)tokenCacheClear:(CDVInvokedUrlCommand *)command;
- (void)tokenCacheReadItems:(CDVInvokedUrlCommand *)command;
- (void)tokenCacheDeleteItem:(CDVInvokedUrlCommand *)command;

+ (OIDCAuthenticationContext *)getOrCreateAuthContext:(NSString *)authority
                                        tokenEndpoint:(NSString *)tokenEndpoint
                                         responseType:(NSString *)responseType
                                    validateAuthority:(BOOL)validate;

- (void)setLogger:(CDVInvokedUrlCommand *)command;
- (void)setLogLevel:(CDVInvokedUrlCommand *) command;

+ (id) objectOrNilFrom:(NSArray *)arguments
              forIndex:(NSUInteger)index;

@end
