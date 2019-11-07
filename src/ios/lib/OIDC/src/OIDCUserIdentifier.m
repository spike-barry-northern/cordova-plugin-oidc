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


#import "OIDCUserIdentifier.h"
#import "OIDCLogger+Internal.h"
#import "OIDCErrorCodes.h"
#import "OIDCUserInformation.h"

#define DEFAULT_USER_TYPE RequiredDisplayableId

@implementation OIDCUserIdentifier

@synthesize userId = _userId;
@synthesize type = _type;

+ (OIDCUserIdentifier*)identifierWithId:(NSString*)userId
{
    OIDCUserIdentifier* identifier = [[OIDCUserIdentifier alloc] init];
    if (!identifier)
    {
        return nil;
    }
    
    identifier->_userId = [OIDCUserInformation normalizeUserId:userId];
    identifier->_type = DEFAULT_USER_TYPE;
    
    return identifier;
}

+ (OIDCUserIdentifier*)identifierWithId:(NSString*)userId
                                 type:(OIDCUserIdentifierType)type
{
    OIDCUserIdentifier* identifier = [[OIDCUserIdentifier alloc] init];
    if (!identifier)
    {
        return nil;
    }
    
    identifier->_userId = [OIDCUserInformation normalizeUserId:userId];
    identifier->_type = type;
    
    return identifier;
}

+ (OIDCUserIdentifier*)identifierWithId:(NSString *)userId
                       typeFromString:(NSString*)type
{
    OIDCUserIdentifier* identifier = [[OIDCUserIdentifier alloc] init];
    if (!identifier)
    {
        return nil;
    }
    
    identifier->_userId = [OIDCUserInformation normalizeUserId:userId];
    identifier->_type = [OIDCUserIdentifier typeFromString:type];
    
    return identifier;
}

+ (BOOL)identifier:(OIDCUserIdentifier*)identifier
       matchesInfo:(OIDCUserInformation*)info
{
    if (!identifier)
    {
        return YES;
    }
    
    OIDCUserIdentifierType type = [identifier type];
    if (type == OptionalDisplayableId)
    {
        return YES;
    }
    
    if (!info)
    {
        return NO;
    }
    
    NSString* matchString = [identifier userIdMatchString:info];
    if (!matchString || [matchString isEqualToString:identifier.userId])
    {
        return YES;
    }
    
    return NO;
}

- (id)copyWithZone:(NSZone*)zone
{
    OIDCUserIdentifier* identifier = [[OIDCUserIdentifier allocWithZone:zone] init];
    if (!identifier)
    {
        return nil;
    }
    
    identifier->_type = _type;
    identifier->_userId = [_userId copyWithZone:zone];
    
    return identifier;
}

- (NSString*)userIdMatchString:(OIDCUserInformation*)info
{
    switch(_type)
    {
        case UniqueId: return info.uniqueId;
        case OptionalDisplayableId: return nil;
        case RequiredDisplayableId: return info.userId;
    }
    
    NSString* log = [NSString stringWithFormat:@"Unrecognized type on identifier match: %d", _type];
    OIDC_LOG_ERROR(log, OIDC_ERROR_UNEXPECTED, nil, nil);
    
    return nil;
}

#define ENUM_TO_STRING_CASE(_val) case _val: return @#_val;

- (NSString*)typeAsString
{
    return [OIDCUserIdentifier stringForType:_type];
}

+ (NSString*)stringForType:(OIDCUserIdentifierType)type
{
    switch (type)
    {
        ENUM_TO_STRING_CASE(UniqueId);
        ENUM_TO_STRING_CASE(OptionalDisplayableId);
        ENUM_TO_STRING_CASE(RequiredDisplayableId);
    }
}

- (BOOL)isDisplayable
{
    return (_type == RequiredDisplayableId || _type == OptionalDisplayableId);
}

#define CHECK_TYPE(_type) if( [@#_type isEqualToString:type] ) { return _type; }
+ (OIDCUserIdentifierType)typeFromString:(NSString*)type
{
    if (!type)
    {
        // If we don't get a type string then just return default
        return DEFAULT_USER_TYPE;
    }
    
    CHECK_TYPE(UniqueId);
    CHECK_TYPE(OptionalDisplayableId);
    CHECK_TYPE(RequiredDisplayableId);
    
    // If it didn't match against a known type return default, but log an error
    NSString* log = [NSString stringWithFormat:@"Did not recognize type \"%@\"", type];
    OIDC_LOG_ERROR(log, OIDC_ERROR_UNEXPECTED, nil, nil);
    return DEFAULT_USER_TYPE;
}

@end
