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

//
//  This class provides a OIDCTokenCacheAccessor interface around the provided OIDCCacheStorage interface.
//
//  This class deserializes the token cache from the data blob provided by the developer on a -deserialize
//  call and validates cache format.
//
//  Note, this class is only used on Mac OS X. On iOS the only suppport caching interface is
//  OIDCKeychainTokenCache.
//
//  The cache itself is a serialized collection of object and dictionaries in the following schema:
//
//  root
//    |- version - a NSString with a number specify the version of the cache
//    |- tokenCache - an NSDictionary
//          |- tokens   - a NSDictionary containing all the tokens
//          |     |- [<user_id> - an NSDictionary, keyed off of an NSString of the userId
//          |            |- <OIDCTokenCacheStoreKey> - An OIDCTokenCacheItem, keyed with an OIDCTokenCacheStoreKey

#import "OIDCTokenCache.h"
#import "OIDCAuthenticationError.h"
#import "OIDCLogger+Internal.h"
#import "OIDCErrorCodes.h"
#import "OIDCTokenCacheKey.h"
#import "OIDCTokenCacheItem+Internal.h"
#import "OIDCUserInformation.h"
#import "OIDCTokenCache+Internal.h"
#import "OIDCTokenCacheKey.h"
#import "OIDCAuthenticationSettings.h"
#import "NSString+OIDCHelperMethods.h"
#import "OIDCLogger.h"
#import "OIDCLogger+Internal.h"
#import "OIDCAuthenticationError.h"
#import "OIDCAuthenticationError+Internal.h"
#import "OIDCErrorCodes.h"

#include <pthread.h>

#define CHECK_ERROR(_cond, _code, _details) { \
    if (!(_cond)) { \
        OIDCAuthenticationError* _OIDC_ERROR = [OIDCAuthenticationError errorFromAuthenticationError:_code protocolCode:nil errorDetails:_details correlationId:nil]; \
        if (error) { *error = _OIDC_ERROR; } \
        return NO; \
    } \
}

@implementation OIDCTokenCache

+ (OIDCTokenCache *)defaultCache
{
    static dispatch_once_t once;
    static OIDCTokenCache * cache = nil;
    
    dispatch_once(&once, ^{
        cache = [OIDCTokenCache new];
    });
    
    return cache;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    pthread_rwlock_init(&_lock, NULL);
    
    return self;
}

- (void)dealloc
{
    pthread_rwlock_destroy(&_lock);
}

- (void)setDelegate:(nullable id<OIDCTokenCacheDelegate>)delegate
{
    if (_delegate == delegate)
    {
        return;
    }
    
    int err = pthread_rwlock_wrlock(&_lock);
    if (err != 0)
    {
        OIDC_LOG_ERROR(@"pthread_rwlock_wrlock failed in setDelegate", err, nil, nil);
        return;
    }
    
    _delegate = delegate;
    _cache = nil;
    
    pthread_rwlock_unlock(&_lock);
    
    if (!delegate)
    {
        return;
    }
    
    [_delegate willAccessCache:self];
    
    [_delegate didAccessCache:self];
}

- (nullable NSData *)serialize
{
    if (!_cache)
    {
        return nil;
    }
    
    int err = pthread_rwlock_rdlock(&_lock);
    if (err != 0)
    {
        OIDC_LOG_ERROR(@"pthread_rwlock_rdlock failed in serialize", err, nil, nil);
        return nil;
    }
    NSDictionary* cacheCopy = [_cache mutableCopy];
    pthread_rwlock_unlock(&_lock);
    
    // Using the dictionary @{ key : value } syntax here causes _cache to leak. Yay legacy runtime!
    NSDictionary* wrapper = [NSDictionary dictionaryWithObjectsAndKeys:cacheCopy, @"tokenCache",
                             @CURRENT_WRAPPER_CACHE_VERSION, @"version", nil];
    
    @try
    {
        return [NSKeyedArchiver archivedDataWithRootObject:wrapper];
    }
    @catch (id exception)
    {
        // This should be exceedingly rare as all of the objects in the cache we placed there.
        OIDC_LOG_ERROR(@"Failed to serialize the cache!", OIDC_ERROR_CACHE_BOIDC_FORMAT, nil, nil);
        return nil;
    }
}

- (id)unarchive:(NSData*)data
          error:(OIDCAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    @try
    {
        return [NSKeyedUnarchiver unarchiveObjectWithData:data];
    }
    @catch (id expection)
    {
        OIDCAuthenticationError* adError =
        [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_CACHE_BOIDC_FORMAT
                                               protocolCode:nil
                                               errorDetails:@"Failed to unarchive data blob from -deserialize!"
                                              correlationId:nil];
        
        if (error)
        {
            *error = adError;
        }
        
        return nil;
    }
}


- (BOOL)deserialize:(nullable NSData*)data
              error:(OIDCAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    pthread_rwlock_wrlock(&_lock);
    BOOL ret = [self deserializeImpl:data error:error];
    pthread_rwlock_unlock(&_lock);
    return ret;
}

- (BOOL)deserializeImpl:(nullable NSData*)data
              error:(OIDCAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    // If they pass in nil on deserialize that means to drop the cache
    if (!data)
    {
        _cache = nil;
        return YES;
    }
    
    id cache = [self unarchive:data error:error];
    if (!cache)
    {
        return NO;
    }
    
    if (![self validateCache:cache error:error])
    {
        return NO;
    }
    
    _cache = [cache objectForKey:@"tokenCache"];
    return YES;
}


- (BOOL)updateCache:(NSData*)data
              error:(OIDCAuthenticationError * __autoreleasing *)error
{
    if (!data)
    {
        if (_cache)
        {
            OIDC_LOG_WARN(@"nil data provided to -updateCache, dropping old cache", nil, nil);
            _cache = nil;
        }
        else
        {
            OIDC_LOG_INFO(@"No data provided for cache.", nil, nil);
        }
        return YES;
    }
    
    // Unarchive the data first
    NSDictionary* dict = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    CHECK_ERROR(dict, OIDC_ERROR_CACHE_BOIDC_FORMAT, @"Unable to unarchive data provided by cache storage!");

    if (![self validateCache:dict error:error])
    {
        return NO;
    }
    
    _cache = [dict objectForKey:@"tokenCache"];
    
    return YES;
}

#pragma mark -

- (void)addToItems:(nonnull NSMutableArray *)items
    fromDictionary:(nonnull NSDictionary *)dictionary
               key:(nonnull OIDCTokenCacheKey *)key
{
    OIDCTokenCacheItem* item = [dictionary objectForKey:key];
    if (item)
    {
        item = [item copy];
        
        [items addObject:item];
    }
}

- (void)addToItems:(nonnull NSMutableArray *)items
         forUserId:(nonnull NSString *)userId
            tokens:(nonnull NSDictionary *)tokens
               key:(OIDCTokenCacheKey *)key
{
    NSDictionary* userTokens = [tokens objectForKey:userId];
    if (!userTokens)
    {
        return;
    }
    
    // Add items matching the key for this user
    if (key)
    {
        [self addToItems:items fromDictionary:userTokens key:key];
    }
    else
    {
        for (id adkey in userTokens)
        {
            [self addToItems:items fromDictionary:userTokens key:adkey];
        }
    }
}

- (NSArray<OIDCTokenCacheItem *> *)getItemsImplKey:(nullable OIDCTokenCacheKey *)key
                                          userId:(nullable NSString *)userId
{
    if (!_cache)
    {
        return nil;
    }
    
    NSDictionary* tokens = [_cache objectForKey:@"tokens"];
    if (!tokens)
    {
        return nil;
    }
    
    NSMutableArray* items = [NSMutableArray new];
    
    if (userId)
    {
        // If we have a specified userId then we only look for that one
        [self addToItems:items forUserId:userId tokens:tokens key:key];
    }
    else
    {
        // Otherwise we have to traverse all of the users in the cache
        for (NSString* userId in tokens)
        {
            [self addToItems:items forUserId:userId tokens:tokens key:key];
        }
    }
    
    return items;
}


/*! Clears token cache details for specific keys.
    @param item The item to remove from the array.
 */
- (BOOL)removeItem:(OIDCTokenCacheItem *)item
             error:(OIDCAuthenticationError * __autoreleasing *)error
{
    [_delegate willWriteCache:self];
    int err = pthread_rwlock_wrlock(&_lock);
    if (err != 0)
    {
        OIDC_LOG_ERROR(@"pthread_rwlock_wrlock failed in removeItem", err, nil, nil);
        return NO;
    }
    BOOL result = [self removeImpl:item error:error];
    pthread_rwlock_unlock(&_lock);
    [_delegate didWriteCache:self];
    return result;
}

- (BOOL)removeImpl:(OIDCTokenCacheItem *)item
             error:(OIDCAuthenticationError * __autoreleasing *)error
{
    OIDCTokenCacheKey* key = [item extractKey:error];
    if (!key)
    {
        return NO;
    }
    
    NSString* userId = item.userInformation.userId;
    if (!userId)
    {
        userId = @"";
    }
    
    NSMutableDictionary* tokens = [_cache objectForKey:@"tokens"];
    if (!tokens)
    {
        return YES;
    }
    
    NSMutableDictionary* userTokens = [tokens objectForKey:userId];
    if (!userTokens)
    {
        return YES;
    }
    
    if (![userTokens objectForKey:key])
    {
        return YES;
    }
    
    [userTokens removeObjectForKey:key];
    
    // Check to see if we need to remove the overall dict
    if (!userTokens.count)
    {
        [tokens removeObjectForKey:userId];
    }
    
    return YES;
}

/*! Return a copy of all items. The array will contain OIDCTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<OIDCTokenCacheItem *> *)allItems:(OIDCAuthenticationError * __autoreleasing *)error
{
    NSArray<OIDCTokenCacheItem *> * items = [self getItemsWithKey:nil userId:nil correlationId:nil error:error];
    return [self filterOutTombstones:items];
}

-(NSMutableArray*)filterOutTombstones:(NSArray*) items
{
    if(!items)
    {
        return nil;
    }
    
    NSMutableArray* itemsKept = [NSMutableArray new];
    for (OIDCTokenCacheItem* item in items)
    {
        if (![item tombstone])
        {
            [itemsKept addObject:item];
        }
    }
    return itemsKept;
}

@end


@implementation OIDCTokenCache (Internal)

- (id<OIDCTokenCacheDelegate>)delegate
{
    return _delegate;
}

- (BOOL)validateCache:(NSDictionary*)dict
                error:(OIDCAuthenticationError * __autoreleasing *)error
{
    CHECK_ERROR([dict isKindOfClass:[NSDictionary class]], OIDC_ERROR_CACHE_BOIDC_FORMAT, @"Root level object of cache is not a NSDictionary!");
    
    NSString* version = [dict objectForKey:@"version"];
    CHECK_ERROR(version, OIDC_ERROR_CACHE_BOIDC_FORMAT, @"Missing version number from cache.");
    CHECK_ERROR([version floatValue] <= CURRENT_WRAPPER_CACHE_VERSION, OIDC_ERROR_CACHE_VERSION_MISMATCH, @"Cache is a future unsupported version.");
    
    NSDictionary* cache = [dict objectForKey:@"tokenCache"];
    CHECK_ERROR(cache, OIDC_ERROR_CACHE_BOIDC_FORMAT, @"Missing token cache from data.");
    CHECK_ERROR([cache isKindOfClass:[NSMutableDictionary class]], OIDC_ERROR_CACHE_BOIDC_FORMAT, @"Cache is not a dictionary!");
    
    NSDictionary* tokens = [cache objectForKey:@"tokens"];
    
    if (tokens)
    {
        CHECK_ERROR([tokens isKindOfClass:[NSMutableDictionary class]], OIDC_ERROR_CACHE_BOIDC_FORMAT, @"tokens must be a mutable dictionary.");
        for (id userId in tokens)
        {
            // On the second level we're expecting NSDictionaries keyed off of the user ids (an NSString*)
            CHECK_ERROR([userId isKindOfClass:[NSString class]], OIDC_ERROR_CACHE_BOIDC_FORMAT, @"User ID key is not of the expected class type");
            id userDict = [tokens objectForKey:userId];
            CHECK_ERROR([userDict isKindOfClass:[NSMutableDictionary class]], OIDC_ERROR_CACHE_BOIDC_FORMAT, @"User ID should have mutable dictionaries in the cache");
            
            for (id adkey in userDict)
            {
                // On the first level we're expecting NSDictionaries keyed off of OIDCTokenCacheStoreKey
                CHECK_ERROR([adkey isKindOfClass:[OIDCTokenCacheKey class]], OIDC_ERROR_CACHE_BOIDC_FORMAT, @"Key is not of the expected class type");
                id token = [userDict objectForKey:adkey];
                CHECK_ERROR([token isKindOfClass:[OIDCTokenCacheItem class]], OIDC_ERROR_CACHE_BOIDC_FORMAT, @"Token is not of the expected class type!");
            }
        }
    }
    
    return YES;
}

#pragma mark -
#pragma mark OIDCTokenCacheAccessor Protocol Implementation

/*! May return nil, if no cache item corresponds to the requested key
 @param key The key of the item.
 @param userId The specific user whose item is needed. May be nil, in which
 case the item for the first user in the cache will be returned.
 @param error Will be set only in case of ambiguity. E.g. if userId is nil
 and we have tokens from multiple users. If the cache item is not present,
 the error will not be set. */
- (OIDCTokenCacheItem *)getItemWithKey:(OIDCTokenCacheKey *)key
                              userId:(NSString *)userId
                       correlationId:(NSUUID *)correlationId
                               error:(OIDCAuthenticationError * __autoreleasing *)error
{
    NSArray<OIDCTokenCacheItem *> * items = [self getItemsWithKey:key userId:userId correlationId:correlationId error:error];
    NSArray<OIDCTokenCacheItem *> * itemsExcludingTombstones = [self filterOutTombstones:items];
    
    if (!itemsExcludingTombstones || itemsExcludingTombstones.count == 0)
    {
        for (OIDCTokenCacheItem* item in items)
        {
            [item logMessage:@"Found"
                       level:OIDC_LOG_LEVEL_WARN
               correlationId:correlationId];
        }
        return nil;
    }
    
    if (itemsExcludingTombstones.count == 1)
    {
        return itemsExcludingTombstones.firstObject;
    }
    
    OIDCAuthenticationError* adError =
    [OIDCAuthenticationError errorFromAuthenticationError:OIDC_ERROR_CACHE_MULTIPLE_USERS
                                           protocolCode:nil
                                           errorDetails:@"The token cache store for this resource contains more than one user. Please set the 'userId' parameter to the one that will be used."
                                          correlationId:correlationId];
    if (error)
    {
        *error = adError;
    }
    
    return nil;

}

/*! Extracts the key from the item and uses it to set the cache details. If another item with the
 same key exists, it will be overriden by the new one. 'getItemWithKey' method can be used to determine
 if an item already exists for the same key.
 @param error in case of an error, if this parameter is not nil, it will be filled with
 the error details. */
- (BOOL)addOrUpdateItem:(OIDCTokenCacheItem *)item
          correlationId:(NSUUID *)correlationId
                  error:(OIDCAuthenticationError * __autoreleasing *)error
{
    [_delegate willWriteCache:self];
    int err = pthread_rwlock_wrlock(&_lock);
    if (err != 0)
    {
        OIDC_LOG_ERROR(@"pthread_rwlock_wrlock failed in addOrUpdateItem", err, correlationId, nil);
        return NO;
    }
    BOOL result = [self addOrUpdateImpl:item correlationId:correlationId error:error];
    pthread_rwlock_unlock(&_lock);
    [_delegate didWriteCache:self];
    
    return result;
}

- (BOOL)addOrUpdateImpl:(OIDCTokenCacheItem *)item
          correlationId:(NSUUID *)correlationId
                  error:(OIDCAuthenticationError * __autoreleasing *)error
{
    if (!item)
    {
        OIDCAuthenticationError* adError = [OIDCAuthenticationError errorFromArgument:item argumentName:@"item" correlationId:correlationId];
        if (error)
        {
            *error = adError;
        }
        return NO;
    }
    
    // Copy the item to make sure it doesn't change under us.
    item = [item copy];
    
    OIDCTokenCacheKey* key = [item extractKey:error];
    if (!key)
    {
        return NO;
    }
    
    NSMutableDictionary* tokens = nil;
    
    if (!_cache)
    {
        // If we don't have a cache that means we need to create one.
        _cache = [NSMutableDictionary new];
        tokens = [NSMutableDictionary new];
        [_cache setObject:tokens forKey:@"tokens"];
    }
    else
    {
        tokens = [_cache objectForKey:@"tokens"];
    }
    
    // Grab the userId first
    id userId = item.userInformation.userId;
    if (!userId)
    {
        // If we don't have one (OAUTH case) then use an empty string
        userId = @"";
    }
    
    // Grab the token dictionary for this user id.
    NSMutableDictionary* userDict = [tokens objectForKey:userId];
    if (!userDict)
    {
        userDict = [NSMutableDictionary new];
        [tokens setObject:userDict forKey:userId];
    }
    
    [userDict setObject:item forKey:key];
    return YES;
}

- (NSArray<OIDCTokenCacheItem *> *)getItemsWithKey:(nullable OIDCTokenCacheKey *)key
                                          userId:(nullable NSString *)userId
                                   correlationId:(nullable NSUUID *)correlationId
                                           error:(OIDCAuthenticationError *__autoreleasing *)error
{
    (void)error;
    (void)correlationId;
    
    [_delegate willAccessCache:self];
    int err = pthread_rwlock_rdlock(&_lock);
    if (err != 0)
    {
        OIDC_LOG_ERROR(@"pthread_rwlock_rdlock failed in getItemsWithKey", err, correlationId, nil);
        return nil;
    }
    NSArray<OIDCTokenCacheItem *> * result = [self getItemsImplKey:key userId:userId];
    pthread_rwlock_unlock(&_lock);
    
    [_delegate didAccessCache:self];
    
    return result;
}

- (NSArray<OIDCTokenCacheItem *> *)allTombstones:(OIDCAuthenticationError * __autoreleasing *)error
{
    NSArray* items = [self getItemsWithKey:nil userId:nil correlationId:nil error:error];
    NSMutableArray* tombstones = [NSMutableArray new];
    for (OIDCTokenCacheItem* item in items)
    {
        if ([item tombstone])
        {
            [tombstones addObject:item];
        }
    }
    return tombstones;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"OIDCTokenCache: %@", _cache];
}

@end
