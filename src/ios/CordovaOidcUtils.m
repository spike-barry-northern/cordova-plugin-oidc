/*******************************************************************************
 * Copyright (c) Microsoft Open Technologies, Inc.
 * All Rights Reserved
 * See License in the project root for license information.
 ******************************************************************************/

#import "CordovaOidcUtils.h"

@implementation CordovaOidcUtils

+ (id)OIDCUserInformationToDictionary:(OIDCUserInformation *)obj
{
    if (!obj)
    {
        return [NSNull null];
    }

    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithCapacity:1];

    [dict setObject:ObjectOrNull(obj.userId) forKey:@"userId"];
    if ([obj userIdDisplayable])
    {
        [dict setObject:ObjectOrNull(obj.userId) forKey:@"displayableId"];
    }
    [dict setObject:ObjectOrNull([obj userId]) forKey:@"uniqueId"];
    [dict setObject:ObjectOrNull([obj familyName]) forKey:@"familyName"];
    [dict setObject:ObjectOrNull([obj givenName]) forKey:@"givenName"];
    [dict setObject:ObjectOrNull([obj identityProvider]) forKey:@"identityProvider"];
    [dict setObject:ObjectOrNull([obj tenantId]) forKey:@"tenantId"];
    return dict;
}

+ (NSMutableDictionary *)OIDCAuthenticationResultToDictionary:(OIDCAuthenticationResult *)obj
{
    NSMutableDictionary *dict = (obj.status == OIDC_SUCCEEDED) ? [CordovaAdalUtils OIDCTokenCacheStoreItemToDictionary:obj.tokenCacheItem] : [CordovaAdalUtils OIDCAuthenticationErrorToDictionary:obj.error];

    [dict setObject:[NSNumber numberWithInt:obj.status] forKey:@"statusCode"];

    return dict;
}


+ (NSMutableDictionary *)OIDCAuthenticationErrorToDictionary:(OIDCAuthenticationError *)obj
{
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithCapacity:1];
    [dict setObject:ObjectOrNull(stringForOIDCErrorCode(obj.code)) forKey:@"errorCode"];
    [dict setObject:ObjectOrNull(obj.protocolCode) forKey:@"error"];
    [dict setObject:ObjectOrNull(obj.errorDetails) forKey:@"errorDescription"];
    return dict;
}

+ (NSMutableDictionary *)OIDCTokenCacheStoreItemToDictionary:(OIDCTokenCacheItem *)obj
{
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithCapacity:1];

    [dict setObject:ObjectOrNull(obj.resource) forKey:@"resource"];
    [dict setObject:ObjectOrNull(obj.authority) forKey:@"authority"];
    [dict setObject:ObjectOrNull(obj.clientId) forKey:@"clientId"];
    [dict setObject:ObjectOrNull(obj.accessToken) forKey:@"accessToken"];
    [dict setObject:ObjectOrNull(obj.accessTokenType) forKey:@"accessTokenType"];
    [dict setObject:[NSNumber numberWithBool:obj.refreshToken != nil] forKey:@"isMultipleResourceRefreshToken"];

    if (obj.expiresOn) // could be nil
    {
        [dict setObject:[NSNumber numberWithDouble:[obj.expiresOn timeIntervalSince1970] * 1000] forKey:@"expiresOn"];
    }

    if (obj.userInformation)
    {
        [dict setObject:[CordovaAdalUtils OIDCUserInformationToDictionary:obj.userInformation] forKey:@"userInfo"];
        [dict setObject:ObjectOrNull([obj.userInformation tenantId]) forKey:@"tenantId"];
        [dict setObject:ObjectOrNull(obj.userInformation.rawIdToken) forKey:@"idToken"];
    }

    return dict;
}

static id ObjectOrNull(id object)
{
    return object ?: [NSNull null];
}

+ (NSString *)mapUserIdToUserName:(OIDCAuthenticationContext *)authContext
                           userId:(NSString *)userId
{
    // not nil or empty string
    if (userId && [userId length] > 0)
    {
        OIDCAuthenticationError *error;

        OIDCKeychainTokenCache* cacheStore = [OIDCKeychainTokenCache new];
        NSArray *cacheItems = [cacheStore allItems:&error];

        if (error == nil)
        {
            for (OIDCTokenCacheItem *obj in cacheItems)
            {
                if ([userId caseInsensitiveCompare:obj.userInformation.userObjectId] == NSOrderedSame || [userId caseInsensitiveCompare:obj.userInformation.uniqueId] == NSOrderedSame)
                {
                    return obj.userInformation.userId;
                }
            }
        }
    }
    return userId;
}

static NSString* stringForOIDCErrorCode(NSInteger code)
{
    NSDictionary* errorCodes = @{
                                 [NSNumber numberWithInt:0]:    @"OIDC_ERROR_SUCCEEDED",
                                 [NSNumber numberWithInt:-1]:   @"OIDC_ERROR_UNEXPECTED",
                                 [NSNumber numberWithInt:100]:  @"OIDC_ERROR_DEVELOPER_INVALID_ARGUMENT",
                                 [NSNumber numberWithInt:101]:  @"OIDC_ERROR_DEVELOPER_AUTHORITY_VALIDATION",
                                 [NSNumber numberWithInt:200]:  @"OIDC_ERROR_SERVER_USER_INPUT_NEEDED",
                                 [NSNumber numberWithInt:201]:  @"OIDC_ERROR_SERVER_WPJ_REQUIRED",
                                 [NSNumber numberWithInt:202]:  @"OIDC_ERROR_SERVER_OAUTH",
                                 [NSNumber numberWithInt:203]:  @"OIDC_ERROR_SERVER_REFRESH_TOKEN_REJECTED",
                                 [NSNumber numberWithInt:204]:  @"OIDC_ERROR_SERVER_WRONG_USER",
                                 [NSNumber numberWithInt:205]:  @"OIDC_ERROR_SERVER_NON_HTTPS_REDIRECT",
                                 [NSNumber numberWithInt:206]:  @"OIDC_ERROR_SERVER_INVALID_ID_TOKEN",
                                 [NSNumber numberWithInt:207]:  @"OIDC_ERROR_SERVER_MISSING_AUTHENTICATE_HEOIDCER",
                                 [NSNumber numberWithInt:208]:  @"OIDC_ERROR_SERVER_AUTHENTICATE_HEOIDCER_BOIDC_FORMAT",
                                 [NSNumber numberWithInt:209]:  @"OIDC_ERROR_SERVER_UNAUTHORIZED_CODE_EXPECTED",
                                 [NSNumber numberWithInt:210]:  @"OIDC_ERROR_SERVER_UNSUPPORTED_REQUEST",
                                 [NSNumber numberWithInt:211]:  @"OIDC_ERROR_SERVER_AUTHORIZATION_CODE",
                                 [NSNumber numberWithInt:300]:  @"OIDC_ERROR_CACHE_MULTIPLE_USERS",
                                 [NSNumber numberWithInt:301]:  @"OIDC_ERROR_CACHE_VERSION_MISMATCH",
                                 [NSNumber numberWithInt:302]:  @"OIDC_ERROR_CACHE_BOIDC_FORMAT",
                                 [NSNumber numberWithInt:303]:  @"OIDC_ERROR_CACHE_NO_REFRESH_TOKEN",
                                 [NSNumber numberWithInt:400]:  @"OIDC_ERROR_UI_MULTLIPLE_INTERACTIVE_REQUESTS",
                                 [NSNumber numberWithInt:401]:  @"OIDC_ERROR_UI_NO_MAIN_VIEW_CONTROLLER",
                                 [NSNumber numberWithInt:402]:  @"OIDC_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION",
                                 [NSNumber numberWithInt:403]:  @"OIDC_ERROR_UI_USER_CANCEL",
                                 [NSNumber numberWithInt:404]:  @"OIDC_ERROR_UI_NOT_ON_MAIN_THREOIDC",
                                 [NSNumber numberWithInt:500]:  @"OIDC_ERROR_TOKENBROKER_UNKNOWN",
                                 [NSNumber numberWithInt:501]:  @"OIDC_ERROR_TOKENBROKER_INVALID_REDIRECT_URI",
                                 [NSNumber numberWithInt:502]:  @"OIDC_ERROR_TOKENBROKER_RESPONSE_HASH_MISMATCH",
                                 [NSNumber numberWithInt:503]:  @"OIDC_ERROR_TOKENBROKER_RESPONSE_NOT_RECEIVED",
                                 [NSNumber numberWithInt:504]:  @"OIDC_ERROR_TOKENBROKER_FAILED_TO_CREATE_KEY",
                                 [NSNumber numberWithInt:505]:  @"OIDC_ERROR_TOKENBROKER_DECRYPTION_FAILED",
                                 [NSNumber numberWithInt:506]:  @"OIDC_ERROR_TOKENBROKER_NOT_A_BROKER_RESPONSE",
                                 [NSNumber numberWithInt:507]:  @"OIDC_ERROR_TOKENBROKER_NO_RESUME_STATE",
                                 [NSNumber numberWithInt:508]:  @"OIDC_ERROR_TOKENBROKER_BOIDC_RESUME_STATE",
                                 [NSNumber numberWithInt:509]:  @"OIDC_ERROR_TOKENBROKER_MISMATCHED_RESUME_STATE",
                                 [NSNumber numberWithInt:510]:  @"OIDC_ERROR_TOKENBROKER_HASH_MISSING",
                                 [NSNumber numberWithInt:511]:  @"OIDC_ERROR_TOKENBROKER_NOT_SUPPORTED_IN_EXTENSION"};

    return [errorCodes objectForKey:[NSNumber numberWithInt:(int)code]];

}

@end
