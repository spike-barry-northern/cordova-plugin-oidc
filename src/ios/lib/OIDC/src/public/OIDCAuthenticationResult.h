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

@class OIDCTokenCacheItem;
@class OIDCAuthenticationError;

typedef enum
{
    /*! Everything went ok. The result object can be used directly. */
    OIDC_SUCCEEDED,
    
    /*! User cancelled the action to supply credentials. */
    OIDC_USER_CANCELLED,
    
    /*! Some error occurred. See the "error" field for details.*/
    OIDC_FAILED,
    
} OIDCAuthenticationResultStatus;

/*!
 Represent the authentication result pass to the asynchronous handlers of any operation.
 */
@interface OIDCAuthenticationResult : NSObject
{
@protected
    //See the corresponding properties for details.
    OIDCTokenCacheItem*               _tokenCacheItem;
    OIDCAuthenticationResultStatus    _status;
    OIDCAuthenticationError*          _error;
    NSUUID*                         _correlationId;
    BOOL                            _multiResourceRefreshToken;
    BOOL                            _extendedLifeTimeToken;
}

/*! See the OIDCAuthenticationResultStatus details */
@property (readonly) OIDCAuthenticationResultStatus status;

/*! A valid access token, if the results indicates success. The property is 
 calculated from the tokenCacheItem one. The property is nil, in 
 case of error.*/
@property (readonly) NSString* accessToken;

@property (readonly) OIDCTokenCacheItem* tokenCacheItem;

/*! The error that occurred or nil, if the operation was successful */
@property (readonly) OIDCAuthenticationError* error;

/*! Set to YES, if part of the result contains a refresh token, which is a multi-resource
 refresh token. */
@property (readonly) BOOL multiResourceRefreshToken;

/*! The correlation ID of the request(s) that get this result. */
@property (readonly) NSUUID* correlationId;

/*! Some access tokens have extended lifetime when server is in an unavailable state.
 This property indicates whether the access token is returned in such a state. */
@property (readonly) BOOL extendedLifeTimeToken;

@end

