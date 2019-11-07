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

#define CURRENT_WRAPPER_CACHE_VERSION 1.0

@class OIDCAuthenticationError;
@class OIDCTokenCache;
@class OIDCTokenCacheItem;

@protocol OIDCTokenCacheDelegate <NSObject>

- (void)willAccessCache:(nonnull OIDCTokenCache *)cache;
- (void)didAccessCache:(nonnull OIDCTokenCache *)cache;
- (void)willWriteCache:(nonnull OIDCTokenCache *)cache;
- (void)didWriteCache:(nonnull OIDCTokenCache *)cache;

@end

@interface OIDCTokenCache : NSObject
{
    NSMutableDictionary* _cache;
    id<OIDCTokenCacheDelegate> _delegate;
    pthread_rwlock_t _lock;
}

/*! Returns the default cache object using the OIDCTokenCacheDelegate set in
    OIDCAuthenticationSettings */
+ (nonnull OIDCTokenCache *)defaultCache;

- (void)setDelegate:(nullable id<OIDCTokenCacheDelegate>)delegate;

- (nullable NSData *)serialize;
- (BOOL)deserialize:(nullable NSData*)data
              error:(OIDCAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (nullable NSArray<OIDCTokenCacheItem *> *)allItems:(OIDCAuthenticationError * __nullable __autoreleasing * __nullable)error;
- (BOOL)removeItem:(nonnull OIDCTokenCacheItem *)item
             error:(OIDCAuthenticationError * __nullable __autoreleasing * __nullable)error;

@end
