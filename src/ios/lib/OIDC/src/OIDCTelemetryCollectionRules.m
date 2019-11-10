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

#import "OIDCTelemetryCollectionRules.h"
#import "OIDCTelemetryEventStrings.h"

static NSDictionary *_telemetryEventRules;

@implementation OIDCTelemetryCollectionRules

+ (void)initialize
{
    _telemetryEventRules = @{
                             // Collect only
                             OIDC_TELEMETRY_KEY_AUTHORITY_TYPE: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_AUTHORITY_VALIDATION_STATUS: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_PROMPT_BEHAVIOR: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_RESULT_STATUS: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_IDP: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_TENANT_ID: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_USER_ID: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_START_TIME: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_END_TIME: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_RESPONSE_TIME: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_DEVICE_ID: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_APPLICATION_NAME: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_APPLICATION_VERSION: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_LOGIN_HINT: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_BROKER_VERSION: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_BROKER_PROTOCOL_VERSION: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_BROKER_APP: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_BROKER_APP_USED: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_CLIENT_ID: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_API_ID: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_TOKEN_TYPE: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_RT_STATUS: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_MRRT_STATUS: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_FRT_STATUS: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_IS_SUCCESSFUL: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_CORRELATION_ID: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_IS_EXTENED_LIFE_TIME_TOKEN: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_API_ERROR_CODE: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_PROTOCOL_CODE: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_ERROR_DESCRIPTION: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_ERROR_DOMAIN: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_HTTP_METHOD: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_HTTP_PATH: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_HTTP_RESPONSE_METHOD: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_REQUEST_QUERY_PARAMS: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_USER_AGENT: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_HTTP_ERROR_DOMAIN: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_AUTHORITY: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_GRANT_TYPE: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_API_STATUS: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_EVENT_NAME: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_REQUEST_ID: @(CollectOnly),
                             OIDC_TELEMETRY_KEY_SPE_INFO: @(CollectOnly),
                             
                             // Collect and count
                             OIDC_TELEMETRY_KEY_UI_EVENT_COUNT: @(CollectAndCount),
                             OIDC_TELEMETRY_KEY_HTTP_EVENT_COUNT: @(CollectAndCount),
                             OIDC_TELEMETRY_KEY_CACHE_EVENT_COUNT: @(CollectAndCount),
                             
                             /* Collect and update */
                             // CacheEvent
                             OIDC_TELEMETRY_KEY_IS_RT: @(CollectAndUpdate),
                             OIDC_TELEMETRY_KEY_IS_MRRT: @(CollectAndUpdate),
                             OIDC_TELEMETRY_KEY_IS_FRT: @(CollectAndUpdate),
                             // HTTPEvent
                             OIDC_TELEMETRY_KEY_HTTP_RESPONSE_CODE: @(CollectAndUpdate),
                             OIDC_TELEMETRY_KEY_HTTP_REQUEST_ID_HEOIDCER: @(CollectAndUpdate),
                             OIDC_TELEMETRY_KEY_OAUTH_ERROR_CODE: @(CollectAndUpdate),
                             OIDC_TELEMETRY_KEY_SERVER_ERROR_CODE: @(CollectAndUpdate),
                             OIDC_TELEMETRY_KEY_SERVER_SUBERROR_CODE: @(CollectAndUpdate),
                             OIDC_TELEMETRY_KEY_RT_AGE: @(CollectAndUpdate),
                             // UIEvent
                             OIDC_TELEMETRY_KEY_USER_CANCEL: @(CollectAndUpdate),
                             OIDC_TELEMETRY_KEY_NTLM_HANDLED: @(CollectAndUpdate)
                             };
}

+ (OIDCTelemetryCollectionBehavior)getTelemetryCollectionRule:(NSString *)propertyName
{
    return [[_telemetryEventRules objectForKey:propertyName] intValue];
}

@end
