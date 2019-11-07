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

/*!
    @protocol OIDCDispatcher
 
    Developer should implement it in order to receive telemetry events.
 
    Usage: an instance of OIDCDispatcher implementation is required when registerring dispatcher for OIDCTelemetry.
 */
@protocol OIDCDispatcher <NSObject>

/*!
    Callback function that will be called by OIDC when telemetry events are flushed.
    @param  event        An event is represented by a dictionary of key-value properties.
 */
- (void)dispatchEvent:(nonnull NSDictionary<NSString*, NSString*> *)event;

@end

/*!
    @class OIDCTelemetry
 
    The central class for OIDC telemetry.
 
    Usage: Get a singleton instance of OIDCTelemetry; register a dispatcher for receiving telemetry events.
 */
@interface OIDCTelemetry : NSObject

/*!
    Get a singleton instance of OIDCTelemetry.
 */
+ (nonnull OIDCTelemetry*)sharedInstance;

/*!
    Register a telemetry dispatcher for receiving telemetry events.
    @param dispatcher            An instance of OIDCDispatcher implementation.
    @param aggregationRequired   If set NO, all telemetry events collected by OIDC will be dispatched;
                                 If set YES, OIDC will dispatch only one event for each acquire token call, 
                                    where the event is a brief summary (but with far less details) of all telemetry events for that acquire token call.
 */
- (void)addDispatcher:(nonnull id<OIDCDispatcher>)dispatcher
  aggregationRequired:(BOOL)aggregationRequired;

/*!
 Remove a telemetry dispatcher added for receiving telemetry events.
 @param dispatcher            An instance of OIDCDispatcher implementation added to the dispatches before.
 */
- (void)removeDispatcher:(nonnull id<OIDCDispatcher>)dispatcher;

/*!
 Remove all telemetry dispatchers added to the dispatchers collection.
 */
- (void)removeAllDispatchers;

@end
