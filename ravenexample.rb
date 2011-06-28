#!/usr/bin/ruby

# Copyright (c) 2004 Thomas Counsell
# GPL Licence.  No Warranty Implied.
#
# Example of using the Ruby Raven authentication system.  See Raven for instructions.
#
# Email tamc2@cam.ac.uk with bugs, fixes or suggestions
#
require 'cgi'
require 'raven.rb'

raven = Raven.new
# Set some details about this script to display to the user when authenticating.
raven.description = "Example of a Ruby Raven Application Agent"
raven.message = 'it wishes to demonstrate that authentication works.'
raven.return_url = 'http://localhost:8888/cgi-bin/RubyRaven/ravenexample.rb'
# Can set the return url. If it is not set, then RubyRaven guesses it based on the location of script.  Will fail if not on a different port
# raven.return_url = 'http://localhost/cgi-bin/ravenexample.rb'

cgi = CGI.new('html4')

# Use this method to log the person out.  This does not impact their raven settings, it just forces another trip to raven.
raven.de_authenticate( cgi ) if cgi['logout'] == 'logout'

# This is the method which checks with Raven.
# Use the second form of authenticate if you wish to insist that Raven interacts with the user
unless cgi['interact'] =='interact'
	authentication = raven.authenticate( cgi )
else
	authentication = raven.authenticate( cgi, "this site insists you interact with Raven" , 'yes')
end
	
case authentication
when nil 	# Has set the CGI to re-direct to Raven. DO NOT OUTPUT ANY MORE CGI !
when String 	# The authentication was sucessfull, authentication contains the raven 'principal' variable.
	cgi.out do
		cgi.html do
			cgi.body do
				cgi.h1 {"Raven Authenticated Succeeded with User: #{authentication}" } +
				cgi.p { "Return url:#{raven.return_url}" } +
				cgi.p { "Parameters: #{cgi.params}" } + # All the original get and post parameters are available (as long as session and cookies working)
				cgi.p { "<a href='#{raven.return_url}?logout=logout' >Click to log out of this website</a>" } +
				cgi.p { "<a href='#{raven.return_url}?interact=interact' >Click to force you to log in with Raven</a>" }
				
			end
		end
	end
when Integer 	# The authentication was not sucessfull. authentication contains the raven error code.
	cgi.out do
		cgi.html do
			cgi.body do
				cgi.h1 {"Raven Authentication Failed with Status: #{authentication}" } +
				cgi.p { "Return url:#{raven.return_url}" } +
				cgi.p { "Parameters: #{cgi.params}" } + # All the original get and post parameters are available (as long as session and cookies working).yy
				cgi.p { "<a href='#{raven.return_url}?logout=logout' >Click to log out of this website</a>" }
			end
		end
	end
end

