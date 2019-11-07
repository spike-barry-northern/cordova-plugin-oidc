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

#import "OIDCTestAppSettingsViewController.h"
#import "OIDCTestAppProfileViewController.h"
#import "OIDCTestAppSettings.h"

// Internal OIDC headers
#import "OIDCWorkPlaceJoinUtil.h"
#import "OIDCKeychainUtil.h"
#import "OIDCRegistrationInformation.h"

static NSArray* s_profileRows = nil;
static NSArray* s_deviceRows = nil;

@interface OIDCTestAppSettingsRow : NSObject

@property (nonatomic, retain) NSString* title;
@property (nonatomic, copy) NSString*(^valueBlock)();
@property (nonatomic, copy) void(^action)();

+ (OIDCTestAppSettingsRow*)rowWithTitle:(NSString *)title;

@end

@implementation OIDCTestAppSettingsRow

+ (OIDCTestAppSettingsRow*)rowWithTitle:(NSString *)title
{
    OIDCTestAppSettingsRow* row = [OIDCTestAppSettingsRow new];
    row.title = title;
    return row;
}

+ (OIDCTestAppSettingsRow*)rowWithTitle:(NSString *)title
                                value:(NSString*(^)())value
{
    OIDCTestAppSettingsRow* row = [OIDCTestAppSettingsRow new];
    row.title = title;
    row.valueBlock = value;
    return row;
}

@end

@interface OIDCTestAppSettingsViewController () <UITableViewDelegate, UITableViewDataSource>

@end

@implementation OIDCTestAppSettingsViewController
{
    UITableView* _tableView;
    
    NSArray* _profileRows;
    NSArray* _deviceRows;
    
    NSString* _keychainId;
    NSString* _wpjState;
}

#define SETTING_ROW(_SETTING) \
    OIDCTestAppSettingsRow* _SETTING = [OIDCTestAppSettingsRow rowWithTitle:@#_SETTING]; \
    _SETTING.valueBlock = ^NSString *{ return OIDCTestAppSettings.settings._SETTING; }

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    self.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Settings"
                                                    image:[UIImage imageNamed:@"Settings"]
                                                      tag:0];
    
    
    NSString* teamId = [OIDCKeychainUtil keychainTeamId:nil];
    _keychainId = teamId ? teamId : @"<No Team ID>";
    
    OIDCTestAppSettingsRow* profileRow = [OIDCTestAppSettingsRow rowWithTitle:@"profile"];
    profileRow.valueBlock = ^NSString *{ return OIDCTestAppSettings.currentProfileTitle; };
    profileRow.action = ^{ [self gotoProfile:nil]; };
    SETTING_ROW(authority);
    SETTING_ROW(clientId);
    SETTING_ROW(resource);
    OIDCTestAppSettingsRow* redirectUri = [OIDCTestAppSettingsRow rowWithTitle:@"redirectUri"];
    redirectUri.valueBlock = ^NSString *{ return [OIDCTestAppSettings.settings.redirectUri absoluteString]; };
    
    _profileRows = @[ profileRow, authority, clientId, redirectUri, resource];
    
    
    
    _deviceRows = @[ [OIDCTestAppSettingsRow rowWithTitle:@"TeamID" value:^NSString *{ return _keychainId; }],
                     [OIDCTestAppSettingsRow rowWithTitle:@"WPJ State" value:^NSString *{ return _wpjState; }]];
    
    return self;
}

- (void)loadView
{
    CGRect screenFrame = UIScreen.mainScreen.bounds;
    _tableView = [[UITableView alloc] initWithFrame:screenFrame];
    _tableView.delegate = self;
    _tableView.dataSource = self;
    _tableView.allowsSelection = YES;
    
    self.view = _tableView;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
}



- (void)viewWillAppear:(BOOL)animated
{
    OIDCRegistrationInformation* regInfo =
    [OIDCWorkPlaceJoinUtil getRegistrationInformation:nil error:nil];
    
    NSString* wpjLabel = @"No WPJ Registration Found";
    
    if (regInfo)
    {
        wpjLabel = @"WPJ Registration Found";
    }
    
    _wpjState = wpjLabel;
    
    self.navigationController.navigationBarHidden = YES;
    
    [_tableView reloadData];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    if (section == 0)
        return _profileRows.count;
    if (section == 1)
        return _deviceRows.count;
    
    return 0;
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView;
{
    return 2;
}

- (nullable NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    if (section == 0)
        return @"Authentication Settings";
    if (section == 1)
        return @"Device State";
    
    return nil;
}


- (OIDCTestAppSettingsRow*)rowForIndexPath:(NSIndexPath *)indexPath
{
    NSInteger section = [indexPath indexAtPosition:0];
    NSInteger row = [indexPath indexAtPosition:1];
    
    if (section == 0)
    {
        return _profileRows[row];
    }
    
    if (section == 1)
    {
        return _deviceRows[row];
    }
    
    return nil;
}

- (nullable NSIndexPath *)tableView:(UITableView *)tableView willSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    OIDCTestAppSettingsRow* row = [self rowForIndexPath:indexPath];
    if (!row.action)
        return nil;
    
    row.action();
    return nil;
}

// Row display. Implementers should *always* try to reuse cells by setting each cell's reuseIdentifier and querying for available reusable cells with dequeueReusableCellWithIdentifier:
// Cell gets various attributes set automatically based on table (separators) and data source (accessory views, editing controls)

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:@"settingsCell"];
    if (!cell)
    {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"settingsCell"];
    }
    
    OIDCTestAppSettingsRow* row = [self rowForIndexPath:indexPath];
    cell.textLabel.text = row.title;
    cell.detailTextLabel.text = row.valueBlock();
    
    if (row.action)
    {
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    
    return cell;
}

- (void)tableView:(UITableView *)tableView accessoryButtonTappedForRowWithIndexPath:(NSIndexPath *)indexPath
{
    OIDCTestAppSettingsRow* row = [self rowForIndexPath:indexPath];
    row.action();
}

- (IBAction)gotoProfile:(id)sender
{
    [self.navigationController pushViewController:[OIDCTestAppProfileViewController sharedProfileViewController] animated:YES];
}

@end
