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

#import "OIDCTelemetryEventStrings.h"


// Telemetry event name
NSString *const OIDC_TELEMETRY_EVENT_API_EVENT              = @"CordovaPlugin.OIDC.api_event";
NSString *const OIDC_TELEMETRY_EVENT_UI_EVENT               = @"CordovaPlugin.OIDC.ui_event";
NSString *const OIDC_TELEMETRY_EVENT_HTTP_REQUEST           = @"CordovaPlugin.OIDC.http_event";
NSString *const OIDC_TELEMETRY_EVENT_LAUNCH_BROKER          = @"CordovaPlugin.OIDC.broker_event";
NSString *const OIDC_TELEMETRY_EVENT_TOKEN_GRANT            = @"CordovaPlugin.OIDC.token_grant";
NSString *const OIDC_TELEMETRY_EVENT_AUTHORITY_VALIDATION   = @"CordovaPlugin.OIDC.authority_validation";
NSString *const OIDC_TELEMETRY_EVENT_ACQUIRE_TOKEN_SILENT   = @"CordovaPlugin.OIDC.acquire_token_silent_handler";
NSString *const OIDC_TELEMETRY_EVENT_AUTHORIZATION_CODE     = @"CordovaPlugin.OIDC.authorization_code";
NSString *const OIDC_TELEMETRY_EVENT_TOKEN_CACHE_LOOKUP     = @"CordovaPlugin.OIDC.token_cache_lookup";
NSString *const OIDC_TELEMETRY_EVENT_TOKEN_CACHE_WRITE      = @"CordovaPlugin.OIDC.token_cache_write";
NSString *const OIDC_TELEMETRY_EVENT_TOKEN_CACHE_DELETE     = @"CordovaPlugin.OIDC.token_cache_delete";

// Telemetry property name, only alphabetic letters, dots, and underscores are allowed.
NSString *const OIDC_TELEMETRY_KEY_EVENT_NAME                   = @"CordovaPlugin.OIDC.event_name";
NSString *const OIDC_TELEMETRY_KEY_AUTHORITY_TYPE               = @"CordovaPlugin.OIDC.authority_type";
NSString *const OIDC_TELEMETRY_KEY_AUTHORITY_VALIDATION_STATUS  = @"CordovaPlugin.OIDC.authority_validation_status";
NSString *const OIDC_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING  = @"CordovaPlugin.OIDC.extended_expires_on_setting";
NSString *const OIDC_TELEMETRY_KEY_PROMPT_BEHAVIOR              = @"CordovaPlugin.OIDC.prompt_behavior";
NSString *const OIDC_TELEMETRY_KEY_RESULT_STATUS                = @"CordovaPlugin.OIDC.status";
NSString *const OIDC_TELEMETRY_KEY_IDP                          = @"CordovaPlugin.OIDC.idp";
NSString *const OIDC_TELEMETRY_KEY_TENANT_ID                    = @"CordovaPlugin.OIDC.tenant_id";
NSString *const OIDC_TELEMETRY_KEY_USER_ID                      = @"CordovaPlugin.OIDC.user_id";
NSString *const OIDC_TELEMETRY_KEY_START_TIME                   = @"CordovaPlugin.OIDC.start_time";
NSString *const OIDC_TELEMETRY_KEY_END_TIME                     = @"CordovaPlugin.OIDC.stop_time";
NSString *const OIDC_TELEMETRY_KEY_RESPONSE_TIME                = @"CordovaPlugin.OIDC.response_time";
NSString *const OIDC_TELEMETRY_KEY_DEVICE_ID                    = @"CordovaPlugin.OIDC.device_id";
NSString *const OIDC_TELEMETRY_KEY_DEVICE_IP_OIDCDRESS            = @"CordovaPlugin.OIDC.device_ip_address";
NSString *const OIDC_TELEMETRY_KEY_APPLICATION_NAME             = @"CordovaPlugin.OIDC.application_name";
NSString *const OIDC_TELEMETRY_KEY_APPLICATION_VERSION          = @"CordovaPlugin.OIDC.application_version";
NSString *const OIDC_TELEMETRY_KEY_LOGIN_HINT                   = @"CordovaPlugin.OIDC.login_hint";
NSString *const OIDC_TELEMETRY_KEY_NTLM_HANDLED                 = @"CordovaPlugin.OIDC.ntlm";
NSString *const OIDC_TELEMETRY_KEY_UI_EVENT_COUNT               = @"CordovaPlugin.OIDC.ui_event_count";
NSString *const OIDC_TELEMETRY_KEY_BROKER_APP                   = @"CordovaPlugin.OIDC.broker_app";
NSString *const OIDC_TELEMETRY_KEY_BROKER_VERSION               = @"CordovaPlugin.OIDC.broker_version";
NSString *const OIDC_TELEMETRY_KEY_BROKER_PROTOCOL_VERSION      = @"CordovaPlugin.OIDC.broker_protocol_version";
NSString *const OIDC_TELEMETRY_KEY_BROKER_APP_USED              = @"CordovaPlugin.OIDC.broker_app_used";
NSString *const OIDC_TELEMETRY_KEY_CLIENT_ID                    = @"CordovaPlugin.OIDC.client_id";
NSString *const OIDC_TELEMETRY_KEY_HTTP_EVENT_COUNT             = @"CordovaPlugin.OIDC.http_event_count";
NSString *const OIDC_TELEMETRY_KEY_CACHE_EVENT_COUNT            = @"CordovaPlugin.OIDC.cache_event_count";
NSString *const OIDC_TELEMETRY_KEY_API_ID                       = @"CordovaPlugin.OIDC.api_id";
NSString *const OIDC_TELEMETRY_KEY_TOKEN_TYPE                   = @"CordovaPlugin.OIDC.token_type";
NSString *const OIDC_TELEMETRY_KEY_IS_RT                        = @"CordovaPlugin.OIDC.is_rt";
NSString *const OIDC_TELEMETRY_KEY_IS_MRRT                      = @"CordovaPlugin.OIDC.is_mrrt";
NSString *const OIDC_TELEMETRY_KEY_IS_FRT                       = @"CordovaPlugin.OIDC.is_frt";
NSString *const OIDC_TELEMETRY_KEY_RT_STATUS                    = @"CordovaPlugin.OIDC.token_rt_status";
NSString *const OIDC_TELEMETRY_KEY_MRRT_STATUS                  = @"CordovaPlugin.OIDC.token_mrrt_status";
NSString *const OIDC_TELEMETRY_KEY_FRT_STATUS                    = @"CordovaPlugin.OIDC.token_frt_status";
NSString *const OIDC_TELEMETRY_KEY_IS_SUCCESSFUL                = @"CordovaPlugin.OIDC.is_successfull";
NSString *const OIDC_TELEMETRY_KEY_CORRELATION_ID               = @"CordovaPlugin.OIDC.correlation_id";
NSString *const OIDC_TELEMETRY_KEY_IS_EXTENED_LIFE_TIME_TOKEN   = @"CordovaPlugin.OIDC.is_extended_life_time_token";
NSString *const OIDC_TELEMETRY_KEY_API_ERROR_CODE               = @"CordovaPlugin.OIDC.api_error_code";
NSString *const OIDC_TELEMETRY_KEY_PROTOCOL_CODE                = @"CordovaPlugin.OIDC.error_protocol_code";
NSString *const OIDC_TELEMETRY_KEY_ERROR_DESCRIPTION            = @"CordovaPlugin.OIDC.error_description";
NSString *const OIDC_TELEMETRY_KEY_ERROR_DOMAIN                 = @"CordovaPlugin.OIDC.error_domain";
NSString *const OIDC_TELEMETRY_KEY_HTTP_METHOD                  = @"CordovaPlugin.OIDC.method";
NSString *const OIDC_TELEMETRY_KEY_HTTP_PATH                    = @"CordovaPlugin.OIDC.http_path";
NSString *const OIDC_TELEMETRY_KEY_HTTP_REQUEST_ID_HEOIDCER       = @"CordovaPlugin.OIDC.x_ms_request_id";
NSString *const OIDC_TELEMETRY_KEY_HTTP_RESPONSE_CODE           = @"CordovaPlugin.OIDC.response_code";
NSString *const OIDC_TELEMETRY_KEY_OAUTH_ERROR_CODE             = @"CordovaPlugin.OIDC.oauth_error_code";
NSString *const OIDC_TELEMETRY_KEY_HTTP_RESPONSE_METHOD         = @"CordovaPlugin.OIDC.response_method";
NSString *const OIDC_TELEMETRY_KEY_REQUEST_QUERY_PARAMS         = @"CordovaPlugin.OIDC.query_params";
NSString *const OIDC_TELEMETRY_KEY_USER_AGENT                   = @"CordovaPlugin.OIDC.user_agent";
NSString *const OIDC_TELEMETRY_KEY_HTTP_ERROR_DOMAIN            = @"CordovaPlugin.OIDC.http_error_domain";
NSString *const OIDC_TELEMETRY_KEY_AUTHORITY                    = @"CordovaPlugin.OIDC.authority";
NSString *const OIDC_TELEMETRY_KEY_TOKEN_ENDPOINT               = @"CordovaPlugin.OIDC.token_endpoint";
NSString *const OIDC_TELEMETRY_KEY_GRANT_TYPE                   = @"CordovaPlugin.OIDC.grant_type";
NSString *const OIDC_TELEMETRY_KEY_API_STATUS                   = @"CordovaPlugin.OIDC.api_status";
NSString *const OIDC_TELEMETRY_KEY_REQUEST_ID                   = @"CordovaPlugin.OIDC.request_id";
NSString *const OIDC_TELEMETRY_KEY_USER_CANCEL                  = @"CordovaPlugin.OIDC.user_cancel";
NSString *const OIDC_TELEMETRY_KEY_SERVER_ERROR_CODE            = @"CordovaPlugin.OIDC.server_error_code";
NSString *const OIDC_TELEMETRY_KEY_SERVER_SUBERROR_CODE         = @"CordovaPlugin.OIDC.server_sub_error_code";
NSString *const OIDC_TELEMETRY_KEY_RT_AGE                       = @"CordovaPlugin.OIDC.rt_age";
NSString *const OIDC_TELEMETRY_KEY_SPE_INFO                     = @"CordovaPlugin.OIDC.spe_info";

// Telemetry property value
NSString *const OIDC_TELEMETRY_VALUE_YES                             = @"yes";
NSString *const OIDC_TELEMETRY_VALUE_NO                              = @"no";
NSString *const OIDC_TELEMETRY_VALUE_TRIED                           = @"tried";
NSString *const OIDC_TELEMETRY_VALUE_USER_CANCELLED                  = @"user_cancelled";
NSString *const OIDC_TELEMETRY_VALUE_NOT_FOUND                       = @"not_found";
NSString *const OIDC_TELEMETRY_VALUE_ACCESS_TOKEN                    = @"access_token";
NSString *const OIDC_TELEMETRY_VALUE_MULTI_RESOURCE_REFRESH_TOKEN    = @"multi_resource_refresh_token";
NSString *const OIDC_TELEMETRY_VALUE_FAMILY_REFRESH_TOKEN            = @"family_refresh_token";
NSString *const OIDC_TELEMETRY_VALUE_OAUTH_TOKEN                      = @"OAUTH_access_token_refresh_token";
NSString *const OIDC_TELEMETRY_VALUE_BY_CODE                         = @"by_code";
NSString *const OIDC_TELEMETRY_VALUE_BY_REFRESH_TOKEN                = @"by_refresh_token";
NSString *const OIDC_TELEMETRY_VALUE_SUCCEEDED                       = @"succeeded";
NSString *const OIDC_TELEMETRY_VALUE_FAILED                          = @"failed";
NSString *const OIDC_TELEMETRY_VALUE_CANCELLED                       = @"cancelled";
NSString *const OIDC_TELEMETRY_VALUE_UNKNOWN                         = @"unknown";
NSString *const OIDC_TELEMETRY_VALUE_AUTHORITY_OIDC                   = @"oidc";
NSString *const OIDC_TELEMETRY_VALUE_AUTHORITY_OAUTH                  = @"adfs";


