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

#import "OIDCAutoMainViewController.h"
#import "OIDCAutoRequestViewController.h"
#import "OIDCAutoResultViewController.h"
#import "OIDC_Internal.h"
#import "UIApplication+OIDCExtensions.h"
#import "OIDC.h"
#import "OIDCKeychainTokenCache+Internal.h"
#import "OIDCTokenCache+Internal.h"
#import "OIDCTokenCacheKey.h"
#import "OIDCTokenCacheItem+Internal.h"


@interface OIDCAutoMainViewController ()
{
    NSMutableString *_resultLogs;
    
}

@end

@implementation OIDCAutoMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.

    [OIDCLogger setLogCallBack:^(OIDC_LOG_LEVEL logLevel, NSString *message, NSString *additionalInformation, NSInteger errorCode, NSDictionary *userInfo) {
        (void)errorCode;
        (void)userInfo;
        (void)logLevel;
        
        NSString* log = [NSString stringWithFormat:@"%@ %@", message, additionalInformation];
        
        if (_resultLogs)
        {
            [_resultLogs appendString:log];
        }
    }];
    [OIDCLogger setLevel:OIDC_LOG_LEVEL_VERBOSE];
    
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender
{
    (void)sender;
    
    if ([segue.identifier isEqualToString:@"showRequest"])
    {
        OIDCAutoRequestViewController *requestVC = segue.destinationViewController;
        requestVC.completionBlock = sender[@"completionBlock"];
    }
    
    
    if ([segue.identifier isEqualToString:@"showResult"])
    {
        OIDCAutoResultViewController *resultVC = segue.destinationViewController;
        resultVC.resultInfoString = sender[@"resultInfo"];
        resultVC.resultLogsString = sender[@"resultLogs"];
    }
}


- (IBAction)acquireToken:(id)sender
{
    (void)sender;
    
    OIDCAutoParamBlock completionBlock = ^void (NSDictionary<NSString *, NSString *> * parameters)
    {
        _resultLogs = [NSMutableString new];
        
        if(parameters[@"error"])
        {
            [self dismissViewControllerAnimated:NO completion:^{
                [self displayResultJson:parameters[@"error"]
                                   logs:_resultLogs];
            }];
            return;
        }
        
        bool validateAuthority = YES;
        if(parameters[@"validate_authority"])
        {
            validateAuthority = parameters[@"validate_authority"] ? [parameters[@"validate_authority"] boolValue] : YES;
        }
        
        OIDCAuthenticationContext* context =
        [[OIDCAuthenticationContext alloc] initWithAuthority:parameters[@"authority"]
                                         validateAuthority:validateAuthority
                                                     error:nil];
        
        if(parameters[@"use_broker"] && ![parameters[@"use_broker"] boolValue])
        {
            context.credentialsType = OIDC_CREDENTIALS_EMBEDDED;
        }
        
        if(parameters[@"correlation_id"])
        {
            context.correlationId = [[NSUUID alloc] initWithUUIDString:parameters[@"correlation_id"]];
        }
        
        OIDCPromptBehavior promptBehavior = OIDC_PROMPT_AUTO;
        NSString *promptValue = parameters[@"prompt_behavior"];
        if(promptValue)
        {
            if ([[promptValue lowercaseString] isEqualToString:@"refresh_session"])
            {
                promptBehavior = OIDC_PROMPT_REFRESH_SESSION;
            }
            else if ([[promptValue lowercaseString] isEqualToString:@"always"])
            {
                promptBehavior = OIDC_PROMPT_ALWAYS;
            }
        }
        
        NSString *userId = parameters[@"user_identifier"];
        OIDCUserIdentifier *userIdentifier = nil;
        if(userId)
        {
            //default identifier type is RequiredDisplayableId
            userIdentifier = [OIDCUserIdentifier identifierWithId:userId];
            NSString *userIdType = parameters[@"user_identifier_type"];
            if(userIdType)
            {
                if ([[userIdType lowercaseString] isEqualToString:@"unique_id"])
                {
                    userIdentifier = [OIDCUserIdentifier identifierWithId:userId
                                                         typeFromString:@"UniqueId"];
                }
                else if ([[userIdType lowercaseString] isEqualToString:@"optional_displayable"])
                {
                    userIdentifier = [OIDCUserIdentifier identifierWithId:userId
                                                         typeFromString:@"OptionalDisplayableId"];
                }
            }
        }
        
        [context acquireTokenWithResource:parameters[@"resource"]
                                 clientId:parameters[@"client_id"]
                              redirectUri:[NSURL URLWithString:parameters[@"redirect_uri"]]
                           promptBehavior:promptBehavior
                           userIdentifier:userIdentifier
                     extraQueryParameters:parameters[@"extra_qp"]
                          completionBlock:^(OIDCAuthenticationResult *result)
         {
             [self dismissViewControllerAnimated:NO completion:^{
                 [self displayAuthenticationResult:result
                                              logs:_resultLogs];
             }];
         }];
    };

    [self performSegueWithIdentifier:@"showRequest" sender:@{@"completionBlock" : completionBlock}];
}


- (IBAction)acquireTokenSilent:(id)sender
{
    (void)sender;
    
    OIDCAutoParamBlock completionBlock = ^void (NSDictionary<NSString *, NSString *> * parameters)
    {
        _resultLogs = [NSMutableString new];
        
        if(parameters[@"error"])
        {
            [self dismissViewControllerAnimated:NO completion:^{
                [self displayResultJson:parameters[@"error"]
                                   logs:_resultLogs];
            }];
            return;
        }
        
        OIDCAuthenticationContext *context =
        [[OIDCAuthenticationContext alloc] initWithAuthority:parameters[@"authority"]
                                         validateAuthority:[parameters[@"validate_authority"] boolValue]
                                                     error:nil];
        
        if(parameters[@"use_broker"] && ![parameters[@"use_broker"] boolValue])
        {
            context.credentialsType = OIDC_CREDENTIALS_EMBEDDED;
        }
        
        if(parameters[@"correlation_id"])
        {
            context.correlationId = [[NSUUID alloc] initWithUUIDString:parameters[@"correlation_id"]];
        }
        
        [context acquireTokenSilentWithResource:parameters[@"resource"]
                                       clientId:parameters[@"client_id"]
                                    redirectUri:[NSURL URLWithString:parameters[@"redirect_uri"]]
                                         userId:parameters[@"user_identifier"]
                                completionBlock:^(OIDCAuthenticationResult *result)
         {
             [self dismissViewControllerAnimated:NO completion:^{
                 [self displayAuthenticationResult:result
                                              logs:_resultLogs];
             }];
         }];
    };
    [self performSegueWithIdentifier:@"showRequest" sender:@{@"completionBlock" : completionBlock}];
}

- (IBAction)readCache:(id)sender
{
    (void)sender;
    
    OIDCKeychainTokenCache *cache = [OIDCKeychainTokenCache new];
    NSArray *allItems = [cache allItems:nil];
    NSMutableDictionary *cacheDictionary = [NSMutableDictionary new];
    [cacheDictionary setValue:[NSString stringWithFormat:@"%lu", (unsigned long)allItems.count] forKey:@"item_count"];
    
    NSMutableArray *arr = [[NSMutableArray alloc] init];
    for(OIDCTokenCacheItem *item in allItems)
    {
        [arr addObject:[self createDictionaryFromTokenCacheItem:item]];
    }
    
    [cacheDictionary setValue:arr forKey:@"items"];
    
    [self displayResultJson:[self createJsonStringFromDictionary:cacheDictionary]
                       logs:_resultLogs];
}

- (IBAction)clearCache:(id)sender
{
    (void)sender;
    
    OIDCKeychainTokenCache* cache = [OIDCKeychainTokenCache new];
    NSArray* allItems = [cache allItems:nil];
    
    for (id object in allItems) {
        [cache removeItem:object error:nil];
    }
    
    [self displayResultJson:[NSString stringWithFormat:@"{\"cleared_items_count\":\"%lu\"}", (unsigned long)allItems.count]
                       logs:_resultLogs];
}

- (IBAction)invalidateRefreshToken:(id)sender
{
    (void)sender;
    
    OIDCAutoParamBlock completionBlock = ^void (NSDictionary<NSString *, NSString *> * parameters)
    {
        _resultLogs = [NSMutableString new];
        
        if(parameters[@"error"])
        {
            [self dismissViewControllerAnimated:NO completion:^{
                [self displayResultJson:parameters[@"error"]
                                   logs:_resultLogs];
            }];
        }
        
        OIDCKeychainTokenCache *cache = [OIDCKeychainTokenCache new];
        
        OIDCTokenCacheKey *key = [OIDCTokenCacheKey keyWithAuthority:parameters[@"authority"]
                                                        resource:parameters[@"resource"]
                                                        clientId:parameters[@"client_id"]
                                                           error:nil];
        
        NSArray<OIDCTokenCacheItem *> *items = [cache getItemsWithKey:key
                                                             userId:parameters[@"user_id"]
                                                      correlationId:nil
                                                              error:nil];
        
        int refreshTokenCount = 0;
        
        for(OIDCTokenCacheItem *item in items)
        {
            if(item.refreshToken){
                refreshTokenCount++;
                item.refreshToken = @"bad-refresh-token";
                [cache addOrUpdateItem:item correlationId:nil error:nil];
            }
        }
        
        [self dismissViewControllerAnimated:NO completion:^{
            [self displayResultJson:[NSString stringWithFormat:@"{\"invalidated_refresh_token_count\":\"%d\"}", refreshTokenCount]
                               logs:_resultLogs];
        }];
    };
    [self performSegueWithIdentifier:@"showRequest" sender:@{@"completionBlock" : completionBlock}];
}

- (IBAction)expireAccessToken:(id)sender
{
    (void)sender;
    
    OIDCAutoParamBlock completionBlock = ^void (NSDictionary<NSString *, NSString *> *parameters)
    {
        _resultLogs = [NSMutableString new];
        if(parameters[@"error"])
        {
            [self dismissViewControllerAnimated:NO completion:^{
                [self displayResultJson:parameters[@"error"]
                                   logs:_resultLogs];
            }];
            return;
        }
        
        OIDCKeychainTokenCache *cache = [OIDCKeychainTokenCache new];
        OIDCTokenCacheKey *key = [OIDCTokenCacheKey keyWithAuthority:parameters[@"authority"]
                                                        resource:parameters[@"resource"]
                                                        clientId:parameters[@"client_id"]
                                                           error:nil];
        
        NSArray<OIDCTokenCacheItem *> *items = [cache getItemsWithKey:key
                                                             userId:parameters[@"user_id"]
                                                      correlationId:nil
                                                              error:nil];
        
        int accessTokenCount = 0;
        
        for(OIDCTokenCacheItem* item in items)
        {
            if(item.accessToken){
                accessTokenCount++;
                item.expiresOn = [NSDate new];
                [cache addOrUpdateItem:item correlationId:nil error:nil];
            }
        }
        
        [self dismissViewControllerAnimated:NO completion:^{
            [self displayResultJson:[NSString stringWithFormat:@"{\"expired_access_token_count\":\"%d\"}", accessTokenCount]
                               logs:_resultLogs];
        }];
    };
    [self performSegueWithIdentifier:@"showRequest" sender:@{@"completionBlock" : completionBlock}];
}

- (void)displayAuthenticationResult:(OIDCAuthenticationResult *)result logs:(NSString *)resultLogs
{
    [self displayResultJson:[self createJsonFromResult:result] logs:resultLogs];
}

- (void)displayResultJson:(NSString *)resultJson logs:(NSString *)resultLogs
{
    [self performSegueWithIdentifier:@"showResult" sender:@{@"resultInfo":resultJson ? resultJson : @"",
                                                            @"resultLogs":resultLogs ? resultLogs : @""}];
}

- (NSString *)createJsonFromResult:(OIDCAuthenticationResult *)result
{
    NSMutableDictionary *resultDict = [NSMutableDictionary new];
    
    if(result.error){
        [resultDict setValue:result.error.errorDetails forKey:@"error"];
        [resultDict setValue:result.error.description forKey:@"error_description"];
    }
    else {
        NSString * isExtLtString = (result.extendedLifeTimeToken) ? @"true" : @"false";
        [resultDict setValue:isExtLtString forKey:@"extended_lifetime_token"];
        [resultDict addEntriesFromDictionary:[self createDictionaryFromTokenCacheItem:result.tokenCacheItem]];
    }
    
    return [self createJsonStringFromDictionary:resultDict];
}

- (NSDictionary *)createDictionaryFromTokenCacheItem:(OIDCTokenCacheItem *)item
{
    NSMutableDictionary* resultDict = [NSMutableDictionary new];
    [resultDict setValue:item.accessToken forKey:@"access_token"];
    [resultDict setValue:item.refreshToken forKey:@"refresh_token"];
    [resultDict setValue:item.accessTokenType forKey:@"access_token_type"];
    [resultDict setValue:[NSString stringWithFormat:@"%ld", (long)item.expiresOn.timeIntervalSince1970] forKey:@"expires_on"];
    
    
    NSString * isMrrtString = (item.isMultiResourceRefreshToken) ? @"true" : @"false";
    [resultDict setValue:isMrrtString forKey:@"mrrt"];
    
    if(item.userInformation){
        [resultDict setValue:item.userInformation.rawIdToken
                      forKey:@"id_token"];
        [resultDict setValue:item.userInformation.identityProvider
                      forKey:@"identity_provider"];
        [resultDict setValue:item.userInformation.tenantId
                      forKey:@"tenant_id"];
        [resultDict setValue:item.userInformation.givenName
                      forKey:@"given_name"];
        [resultDict setValue:item.userInformation.guestId
                      forKey:@"guest_id"];
        [resultDict setValue:item.userInformation.familyName
                      forKey:@"family_name"];
        [resultDict setValue:item.userInformation.uniqueId
                      forKey:@"unique_id"];
        if(item.userInformation.userIdDisplayable)
        {
            [resultDict setValue:item.userInformation.userId
                          forKey:@"displayable_id"];
        }
    }
    
    return resultDict;
}


- (NSString *)createJsonStringFromDictionary:(NSDictionary *)dictionary
{
    
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dictionary
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];

    if (! jsonData) {
        return [NSString stringWithFormat:@"{\"error\" : \"%@\"}", error.description];
    }
    
    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}


@end
