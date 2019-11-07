Pod::Spec.new do |s|
  s.name         = "OIDC"
  s.module_name  = "OIDC"
  s.version      = "2.5.2"
  s.summary      = "The OIDC SDK for iOS gives you the ability to add Azure Identity authentication to your application"

  s.description  = <<-DESC
                   The Azure Identity Library for Objective C. This library gives you the ability to add support for Work Accounts to your iOS and macOS applications with just a few lines of additional code. This SDK gives your application the full functionality of Microsoft OIDC, including industry standard protocol support for OAuth2, Web API integration with user level consent, and two factor authentication support.
                   DESC
  s.homepage     = "https://github.com/OAUTH/azure-activedirectory-library-for-objc"
  s.license      = { 
    :type => "MIT", 
    :file => "LICENSE.txt" 
  }
  s.authors      = { "Microsoft" => "nugetaad@cordovaplugin.com" }
  s.social_media_url   = "https://twitter.com/azuread"
  s.platform     = :ios, :osx
  s.ios.deployment_target = "9.0"
  s.osx.deployment_target = "10.10"
  s.source       = { 
    :git => "https://github.com/OAUTH/azure-activedirectory-library-for-objc.git", 
    :tag => s.version.to_s
  }
  
  s.default_subspecs ='app-lib'
  
  s.prefix_header_file = "OIDC/src/OIDC.pch"
  s.header_dir = "OIDC"
  s.module_map = "OIDC/resources/mac/oidc_mac.modulemap"
  
  s.subspec 'app-lib' do |app|
  	app.source_files = "OIDC/src/**/*.{h,m}"
  	app.ios.public_header_files = "OIDC/src/public/*.h","OIDC/src/public/ios/*.h"
  	app.osx.public_header_files = "OIDC/src/public/mac/*.h","OIDC/src/public/*.h"
  
  	app.ios.exclude_files = "OIDC/src/**/mac/*"
  		
  	app.osx.exclude_files = "OIDC/src/**/ios/*"
  	app.osx.resources = "OIDC/resources/mac/OIDCCredentialViewController.xib"
  	
  	app.requires_arc = true
  	
  	app.ios.dependency 'OIDC/tokencacheheader'
  end
  
  # This is a hack because one of the headers is public on mac but private on ios
  s.subspec 'tokencacheheader' do |ph|
  	ph.platform = :ios
  	ph.ios.source_files = "OIDC/src/public/mac/OIDCTokenCache.h"
  	# This extra nonsense is so that it doesn't make OIDCTokenCache.h a public header on iOS
  	# And also doesn't generate a podspec warning
  	ph.ios.private_header_files = "OIDC/src/public/mac/OIDCTokenCache.h"
  end
  
  # Note, OIDC has limited support for running in app extensions.
  s.subspec 'extension' do |ext|
  	ext.compiler_flags = '-DOIDC_EXTENSION_SAFE=1'
  	ext.source_files = "OIDC/src/**/*.{h,m}"
  	ext.ios.public_header_files = "OIDC/src/public/*.h","OIDC/src/public/ios/*.h"
  	ext.osx.public_header_files = "OIDC/src/public/mac/*.h","OIDC/src/public/*.h"
  
  	# There is currently a bug in CocoaPods where it doesn't combine the public headers
  	# for both the platform and overall.
  	ext.ios.exclude_files = "OIDC/src/**/mac/*"
  	ext.osx.exclude_files = "OIDC/src/**/ios/*"
  	
  	ext.requires_arc = true
  	
  	ext.ios.dependency 'OIDC/tokencacheheader'
  end
end
