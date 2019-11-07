#!/usr/bin/env python

# Copyright (c) Microsoft Corporation.
# All rights reserved.
#
# This code is licensed under the MIT License.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files(the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions :
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import subprocess
import traceback
import sys
import re
import os

from timeit import default_timer as timer

ios_sim_dest = "-destination 'platform=iOS Simulator,name=iPhone 6,OS=latest'"
ios_sim_flags = "-sdk iphonesimulator CODE_SIGN_IDENTITY=\"\" CODE_SIGNING_REQUIRED=NO"

default_workspace = "OIDC.xcworkspace"
default_config = "Debug"

use_xcpretty = True

class ColorValues:
	HDR = '\033[1m'
	OK = '\033[32m\033[1m'
	FAIL = '\033[31m\033[1m'
	WARN = '\033[33m\033[1m'
	SKIP = '\033[96m\033[1m'
	END = '\033[0m'

target_specifiers = [
	{
		"name" : "iOS Framework",
		"scheme" : "OIDC",
		"operations" : [ "build", "test", "codecov" ],
		"min_warn_codecov" : 70.0,
		"platform" : "iOS",
		"use_sonarcube" : "true"
	},
	{
		"name" : "iOS Test App",
		"scheme" : "MyTestiOSApp",
		"operations" : [ "build" ],
		"platform" : "iOS"
	},
	{
		"name" : "iOS Automation Test App",
		"scheme" : "OIDCAutomation",
		"operations" : [ "build" ],
		"platform" : "iOS"
	},
	{
		"name" : "Sample Swift App",
		"scheme" : "SampleSwiftApp",
		"operations" : [ "build" ],
		"platform" : "iOS",
		"workspace" : "Samples/SampleSwiftApp/SampleSwiftApp.xcworkspace"
	},
	{
		"name" : "Mac Framework",
		"scheme" : "OIDC Mac",
		"operations" : [ "build", "test", "codecov" ],
		"min_warn_codecov" : 70.0,
		"platform" : "Mac"
	},
	{
		"name" : "Mac Test App",
		"scheme" : "MyTestMacOSApp",
		"operations" : [ "build" ],
		"platform" : "Mac"
	}
]

def print_operation_start(name, operation) :
	print ColorValues.HDR + "Beginning " + name + " [" + operation + "]" + ColorValues.END
	print "travis_fold:start:" + (name + "_" + operation).replace(" ", "_")

def print_operation_end(name, operation, exit_code, start_time) :
	print "travis_fold:end:" + (name + "_" + operation).replace(" ", "_")
	
	end_time = timer()

	if (exit_code == 0) :
		print ColorValues.OK + name + " [" + operation + "] Succeeded" + ColorValues.END + " (" + "{0:.2f}".format(end_time - start_time) + " seconds)"
	else :
		print ColorValues.FAIL + name + " [" + operation + "] Failed" + ColorValues.END + " (" + "{0:.2f}".format(end_time - start_time) + " seconds)"

class BuildTarget:
	def __init__(self, target):
		self.name = target["name"]
		self.project = target.get("project")
		self.workspace = target.get("workspace")
		if (self.workspace == None and self.project == None) :
			self.workspace = default_workspace
		self.scheme = target["scheme"]
		self.dependencies = target.get("dependencies")
		self.operations = target["operations"]
		self.platform = target["platform"]
		self.build_settings = None
		self.min_codecov = target.get("min_codecov")
		self.min_warn_codecov = target.get("min_warn_codecov")
		self.use_sonarcube = target.get("use_sonarcube")
		self.coverage = None
		self.failed = False
		self.skipped = False
	
	def xcodebuild_command(self, operation, xcpretty) :
		"""
		Generate and return an xcodebuild command string based on the ivars and operation provided.
		"""
		command = "xcodebuild "
		
		if (operation != None) :
			command += operation + " "
		
		if (self.project != None) :
			command += " -project " + self.project
		else :
			command += " -workspace " + self.workspace
		
		command += " -scheme \"" + self.scheme + "\" -configuration " + default_config
		
		if (operation == "test" and "codecov" in self.operations) :
			command += " -enableCodeCoverage YES"

		if (self.platform == "iOS") :
			command += " " + ios_sim_flags + " " + ios_sim_dest
		
		if (xcpretty) :
			command += " | xcpretty"
		
		return command
	
	def get_build_settings(self) :
		"""
		Retrieve the build settings from xcodebuild and return thm in a dictionary
		"""
		if (self.build_settings != None) :
			return self.build_settings
		
		command = self.xcodebuild_command(None, False)
		command += " -showBuildSettings"
		
		start = timer()
        
		settings_blob = subprocess.check_output(command, shell=True)
		settings_blob = settings_blob.decode("utf-8")
		settings_blob = settings_blob.split("\n")
        
		settings = {}
		
		for line in settings_blob :
			split_line = line.split(" = ")
			if (len(split_line) < 2) :
				continue
			key = split_line[0].strip()
			value = split_line[1].strip()
			
			settings[key] = value
		
		self.build_settings = settings
		
		end = timer()
		
		print "Retrieved Build Settings (" + "{0:.2f}".format(end - start) + " sec)"
		
		return settings
		
	def print_coverage(self, printname) :
		"""
		Print a summary of the code coverage results with the proper coloring and
		return -1 if the coverage is below the minimum required.
		"""
		if (self.coverage == None) :
			return 0;
			
		printed = False
		
		if (self.min_warn_codecov != None and self.coverage < self.min_warn_codecov) :
			sys.stdout.write(ColorValues.WARN)
			if (printname) :
				sys.stdout.write(self.name + ": ")
			sys.stdout.write(str(self.coverage) + "% coverage is below the recommended minimum requirement: " + str(self.min_warn_codecov) + "%" + ColorValues.END + "\n")
			printed = True
				
		if (self.min_codecov != None and self.coverage < self.min_codecov) :
			sys.stdout.write(ColorValues.FAIL)
			if (printname) :
				sys.stdout.write(self.name + ": ")
			sys.stdout.write(str(self.coverage) + "% coverage is below the minimum requirement: " + str(self.min_codecov) + "%" + ColorValues.END + "\n")
			return -1
		
		if (not printed) :
			sys.stdout.write(ColorValues.OK)
			if (printname) :
				sys.stdout.write(self.name + ": ")
			sys.stdout.write(str(self.coverage) + "%" + ColorValues.END + "\n")
			
		return 0
		
	
	def do_codecov(self) :
		"""
		Print a code coverage report using llvm_cov, retrieve the coverage result and
		print out an error if it is below the minimum requirement
		"""
		build_settings = self.get_build_settings();
		objroot = build_settings["OBJROOT"]
		
		# Starting in Xcocde 9 they add ".noindex" to the intermediates, but the code coverage folder is not in that folder
		if (objroot.endswith(".noindex")) :
			objroot = objroot[0:len(objroot) - 8]
		codecov_dir = objroot + "/CodeCoverage"
		executable_path = build_settings["EXECUTABLE_PATH"]
		config = build_settings["CONFIGURATION"]
		platform_name = build_settings.get("EFFECTIVE_PLATFORM_NAME")
		if (platform_name == None) :
			platform_name = ""
		
		command = "xcrun llvm-cov report -instr-profile Coverage.profdata -arch=\"x86_64\" -use-color Products/" + config + platform_name + "/" + executable_path
		print command
		p = subprocess.Popen(command, cwd = codecov_dir, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
		
		output = p.communicate()
		
		last_line = None
		for line in output[0].split("\n") :
			if (len(line.strip()) > 0) :
				last_line = line
		
		sys.stdout.write(output[0])
		sys.stderr.write(output[1])
		
		last_line = last_line.split()
		# Remove everything but 
		cov_str = re.sub(r"[^0-9.]", "", last_line[3])
		self.coverage = float(cov_str)
		return self.print_coverage(False)
		
	
	def do_operation(self, operation) :
		exit_code = -1;
		print_operation_start(self.name, operation)
		start_time = timer()
		
		try :
			if (operation == "codecov") :
				exit_code = self.do_codecov()
			else :
				command = self.xcodebuild_command(operation, use_xcpretty)
				if (operation == "build" and self.use_sonarcube == "true" and os.environ.get('TRAVIS') == "true") :
					subprocess.call("rm -rf .sonar; rm -rf build-wrapper-output", shell = True)
					command = "build-wrapper-macosx-x86 --out-dir build-wrapper-output " + command
				print command
				exit_code = subprocess.call("set -o pipefail;" + command, shell = True)
			
			if (exit_code != 0) :
				self.failed = True
		except Exception as inst:
			self.failed = True
			print "Failed due to exception in build script"
			tb = traceback.format_exc()
			print tb

		print_operation_end(self.name, operation, exit_code, start_time)
		
		print 
		return exit_code

clean = True

for arg in sys.argv :
	if (arg == "--no-clean") :
		clean = False
	if (arg == "--no-xcpretty") :
		use_xcpretty = False
#	if ("--scheme" in arg)
		

targets = []

for spec in target_specifiers :
	targets.append(BuildTarget(spec))

# start by cleaning up any derived data that might be lying around
if (clean) :
	derived_folders = set()
	for target in targets :
		objroot = target.get_build_settings()["OBJROOT"]
		trailing = "/Build/Intermediates"
		derived_dir = objroot[:-len(trailing)]
		derived_folders.add(derived_dir)
		print derived_dir
	
	for dir in derived_folders :
		print "Deleting " + dir
		subprocess.call("rm -rf " + dir, shell=True)

for target in targets:
	exit_code = 0

	for operation in target.operations :
		if (exit_code != 0) :
			break; # If one operation fails, then the others are almost certainly going to fail too

		exit_code = target.do_operation(operation)

	# Add success/failure state to the build status dictionary
	if (exit_code == 0) :
		print ColorValues.OK + target.name + " Succeeded" + ColorValues.END
	else :
		print ColorValues.FAIL + target.name + " Failed" + ColorValues.END

final_status = 0

print "\n"

code_coverage = False

# Print out the final result of each operation.
for target in targets :
	if (target.failed) :
		print ColorValues.FAIL + target.name + " failed." + ColorValues.END
		final_status = 1
	else :
		if ("codecov" in target.operations) :
			code_coverage = True
		print ColorValues.OK + '\033[92m' + target.name + " succeeded." + ColorValues.END

if code_coverage :
	print "\nCode Coverage Results:"
	for target in targets :
		if (target.coverage != None) :
			target.print_coverage(True)

sys.exit(final_status)
