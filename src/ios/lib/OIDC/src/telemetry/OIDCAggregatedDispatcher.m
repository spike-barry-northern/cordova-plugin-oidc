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

#import "OIDCTelemetry.h"
#import "OIDCTelemetryEventInterface.h"
#import "OIDCAggregatedDispatcher.h"
#import "OIDCTelemetryEventStrings.h"
#import "OIDCTelemetryCollectionRules.h"
#import "OIDCTelemetryAPIEvent.h"
#import "OIDCTelemetryUIEvent.h"
#import "OIDCTelemetryHttpEvent.h"
#import "OIDCTelemetryCacheEvent.h"
#import "OIDCTelemetryBrokerEvent.h"
#import "NSMutableDictionary+OIDCExtensions.h"

@implementation OIDCAggregatedDispatcher

static NSDictionary *s_eventPropertiesDictionary;

- (id)init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initWithDispatcher:(id<OIDCDispatcher>)dispatcher
{
    self = [super initWithDispatcher:dispatcher];
    return self;
}

- (void)flush:(NSString*)requestId
{
    [_dispatchLock lock]; //avoid access conflict when manipulating _objectsToBeDispatched
    NSArray* eventsToBeDispatched = [_objectsToBeDispatched objectForKey:requestId];
    [_objectsToBeDispatched removeObjectForKey:requestId];
    [_dispatchLock unlock];
    
    NSMutableDictionary* aggregatedEvent = [NSMutableDictionary new];
    for (id<OIDCTelemetryEventInterface> event in eventsToBeDispatched)
    {
        [self addPropertiesToDictionary:aggregatedEvent event:event];
    }
    
    [_dispatcher dispatchEvent:aggregatedEvent];
}

- (void)receive:(NSString *)requestId
          event:(id<OIDCTelemetryEventInterface>)event
{
    if ([NSString adIsStringNilOrBlank:requestId] || !event)
    {
        return;
        
    }
    
    [_dispatchLock lock]; //make sure no one changes _objectsToBeDispatched while using it
    NSMutableArray* eventsForRequestId = [_objectsToBeDispatched objectForKey:requestId];
    if (!eventsForRequestId)
    {
        eventsForRequestId = [NSMutableArray new];
        [_objectsToBeDispatched setObject:eventsForRequestId forKey:requestId];
    }
    
    [eventsForRequestId addObject:event];
    [_dispatchLock unlock];
    
}

- (void)addPropertiesToDictionary:(NSMutableDictionary*)aggregatedEvent event:(id<OIDCTelemetryEventInterface>)event
{
    [aggregatedEvent addEntriesFromDictionary:[OIDCTelemetryDefaultEvent defaultParameters]];
    
    NSString *eventClassName = NSStringFromClass([event class]);
    
    NSArray* eventProperties = [s_eventPropertiesDictionary objectForKey:eventClassName];
    
    for (NSString* propertyName in eventProperties)
    {
        OIDCTelemetryCollectionBehavior collectionBehavior = [OIDCTelemetryCollectionRules getTelemetryCollectionRule:propertyName];
        
        if (collectionBehavior == CollectAndUpdate)
        {
            //erase the previous event properties only if there were any previously
            if ([aggregatedEvent objectForKey:propertyName])
            {
                [aggregatedEvent removeObjectForKey:propertyName];
            }
        }
        
        if (collectionBehavior != CollectAndCount)
        {
            [aggregatedEvent adSetObjectIfNotNil:[[event getProperties] objectForKey:propertyName] forKey:propertyName];
        }
        else
        {
            int eventCount = [[aggregatedEvent objectForKey:propertyName] intValue];
            [aggregatedEvent setObject:[NSString stringWithFormat:@"%d", ++eventCount] forKey:propertyName];
        }
    }
}

+ (void)initialize
{
    if (self == [OIDCAggregatedDispatcher class])
    {
        s_eventPropertiesDictionary = @{
                                      NSStringFromClass([OIDCTelemetryAPIEvent class]): @[
                                              // default properties apply to all events
                                              OIDC_TELEMETRY_KEY_REQUEST_ID,
                                              OIDC_TELEMETRY_KEY_CORRELATION_ID,
                                              
                                              OIDC_TELEMETRY_KEY_AUTHORITY_TYPE,
                                              OIDC_TELEMETRY_KEY_AUTHORITY_VALIDATION_STATUS,
                                              OIDC_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING,
                                              OIDC_TELEMETRY_KEY_PROMPT_BEHAVIOR,
                                              OIDC_TELEMETRY_KEY_RESULT_STATUS,
                                              OIDC_TELEMETRY_KEY_IDP,
                                              OIDC_TELEMETRY_KEY_TENANT_ID,
                                              OIDC_TELEMETRY_KEY_USER_ID,
                                              OIDC_TELEMETRY_KEY_RESPONSE_TIME,
                                              OIDC_TELEMETRY_KEY_CLIENT_ID,
                                              OIDC_TELEMETRY_KEY_API_ID,
                                              OIDC_TELEMETRY_KEY_USER_CANCEL,
                                              OIDC_TELEMETRY_KEY_API_ERROR_CODE,
                                              OIDC_TELEMETRY_KEY_ERROR_DOMAIN,
                                              OIDC_TELEMETRY_KEY_PROTOCOL_CODE,
                                              OIDC_TELEMETRY_KEY_IS_SUCCESSFUL
                                              ],
                                      NSStringFromClass([OIDCTelemetryUIEvent class]): @[
                                              // default properties apply to all events
                                              OIDC_TELEMETRY_KEY_REQUEST_ID,
                                              OIDC_TELEMETRY_KEY_CORRELATION_ID,
                                              
                                              OIDC_TELEMETRY_KEY_LOGIN_HINT,
                                              OIDC_TELEMETRY_KEY_NTLM_HANDLED,
                                              OIDC_TELEMETRY_KEY_UI_EVENT_COUNT
                                              ],
                                      NSStringFromClass([OIDCTelemetryHttpEvent class]): @[
                                              // default properties apply to all events
                                              OIDC_TELEMETRY_KEY_REQUEST_ID,
                                              OIDC_TELEMETRY_KEY_CORRELATION_ID,
                                              
                                              OIDC_TELEMETRY_KEY_OAUTH_ERROR_CODE,
                                              OIDC_TELEMETRY_KEY_HTTP_RESPONSE_CODE,
                                              OIDC_TELEMETRY_KEY_HTTP_EVENT_COUNT,
                                              OIDC_TELEMETRY_KEY_SERVER_ERROR_CODE,
                                              OIDC_TELEMETRY_KEY_SERVER_SUBERROR_CODE,
                                              OIDC_TELEMETRY_KEY_RT_AGE,
                                              OIDC_TELEMETRY_KEY_SPE_INFO
                                              ],
                                      NSStringFromClass([OIDCTelemetryCacheEvent class]): @[
                                              // default properties apply to all events
                                              OIDC_TELEMETRY_KEY_REQUEST_ID,
                                              OIDC_TELEMETRY_KEY_CORRELATION_ID,
                                              
                                              OIDC_TELEMETRY_KEY_RT_STATUS,
                                              OIDC_TELEMETRY_KEY_FRT_STATUS,
                                              OIDC_TELEMETRY_KEY_MRRT_STATUS,
                                              OIDC_TELEMETRY_KEY_CACHE_EVENT_COUNT,
                                              OIDC_TELEMETRY_KEY_SPE_INFO
                                              ],
                                      NSStringFromClass([OIDCTelemetryBrokerEvent class]): @[
                                              // default properties apply to all events
                                              OIDC_TELEMETRY_KEY_REQUEST_ID,
                                              OIDC_TELEMETRY_KEY_CORRELATION_ID,
                                              
                                              OIDC_TELEMETRY_KEY_BROKER_APP,
                                              OIDC_TELEMETRY_KEY_BROKER_VERSION
                                              ],
                                      };
    }
}

@end
