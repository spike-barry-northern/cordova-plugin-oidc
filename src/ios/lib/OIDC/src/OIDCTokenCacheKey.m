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


#import "OIDC_Internal.h"
#import "OIDCAuthenticationContext.h"
#import "OIDCHelpers.h"
#import "OIDCTokenCacheKey.h"
#import "NSString+OIDCHelperMethods.h"

@implementation OIDCTokenCacheKey

@synthesize authority = _authority;
@synthesize tokenEndpoint = _tokenEndpoint;
@synthesize resource = _resource;
@synthesize clientId = _clientId;

- (void)calculateHash
{
    _hash = [[NSString stringWithFormat:@"##%@##%@##%@##", _authority, _resource, _clientId]
             hash];
}

- (id)initWithAuthority:(NSString *)authority
          tokenEndpoint:(NSString *)tokenEndpoint
           responseType:(NSString *)responseType
               resource:(NSString *)resource
               clientId:(NSString *)clientId
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _authority = authority;
    _tokenEndpoint = tokenEndpoint;
    _responseType = responseType;
    _resource = resource;
    _clientId = clientId;
    
    [self calculateHash];
    
    return self;
}

+ (id)keyWithAuthority:(NSString *)authority
         tokenEndpoint:(NSString *)tokenEndpoint
          responseType:(NSString *)responseType
              resource:(NSString *)resource
              clientId:(NSString *)clientId
                 error:(OIDCAuthenticationError * __autoreleasing *)error
{
    API_ENTRY;
    // Trim first for faster nil or empty checks. Also lowercase and trimming is
    // needed to ensure that the cache handles correctly same items with different
    // character case:
    authority = [OIDCHelpers canonicalizeAuthority:authority];
    tokenEndpoint = tokenEndpoint.adTrimmedString;
    responseType = responseType.adTrimmedString;
    resource = resource.adTrimmedString.lowercaseString;
    clientId = clientId.adTrimmedString.lowercaseString;
    RETURN_NIL_ON_NIL_ARGUMENT(authority);
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(clientId);
    
    OIDCTokenCacheKey* key = [[OIDCTokenCacheKey alloc] initWithAuthority:authority
                                                            tokenEndpoint:tokenEndpoint
                                                             responseType:responseType
                                                                 resource:resource
                                                                 clientId:clientId];
    return key;
}

- (NSUInteger)hash
{
    return _hash;
}

- (BOOL)isEqual:(id)object
{
    if (!object)
    {
        return NO;
    }
    
    if (![object isKindOfClass:[OIDCTokenCacheKey class]])
    {
        return NO;
    }
    
    OIDCTokenCacheKey* key = object;
    
    //First check the fields which cannot be nil:
    if (![self.authority isEqualToString:key.authority] ||
        ![self.clientId isEqualToString:key.clientId])
    {
        return NO;
    }
    
    //Now handle the case of nil resource:
    if (!self.resource)
    {
        return !key.resource;//Both should be nil to be equal
    }
    else
    {
        return [self.resource isEqualToString:key.resource];
    }
}

- (void)encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:self.authority forKey:@"authority"];
    [aCoder encodeObject:self.resource forKey:@"resource"];
    [aCoder encodeObject:self.clientId forKey:@"clientId"];
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _authority = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"authority"];
    _resource = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"resource"];
    _clientId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"clientId"];
    
    [self calculateHash];
    
    return self;
}

+ (BOOL)supportsSecureCoding
{
    return YES;
}

- (id)copyWithZone:(NSZone *) zone
{
    OIDCTokenCacheKey* key = [[OIDCTokenCacheKey allocWithZone:zone] init];
    
    key->_authority = [_authority copyWithZone:zone];
    key->_clientId = [_clientId copyWithZone:zone];
    key->_resource = [_resource copyWithZone:zone];
    
    [key calculateHash];
    
    return key;
}

- (OIDCTokenCacheKey *)mrrtKey
{
    return [[self class] keyWithAuthority:_authority
                            tokenEndpoint:_tokenEndpoint
                             responseType:_responseType
                                 resource:nil
                                 clientId:_clientId
                                    error:nil];
}

@end
