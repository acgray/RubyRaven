#!/usr/local/bin/ruby

# Copyright (c) 2004 Thomas Counsell
# GPL Licence.  No Warranty Implied.
#
# Version Beta2 31 August 2004
# 
# Please see Raven for use instructions.
# You should also have a copy of ravenexample.rb along with this file.
# This gives a basic example of how to use.
#
# Uses the standard library that comes with Ruby 1.8, may be backportable
# to Ruby 1.6 but I haven't tested it.
# 
# Needs the host computer to have OpenSSL correctly installed (done by default on unix and mac?)
#
# Please report any bugs, or make suggestions to Tom Counsell 
# tamc2@cam.ac.uk
#

require 'cgi' 		# To do the CGI stuff
require 'cgi/session' 	# To store the username so that Raven isn't called every time a page is accessed
require 'base64'	# To recode some numbers for the signature authentication
require 'openssl'	# To authenticate the signature
require 'yaml'		# To save the get and post parameters in the session file.

# Two new methods are added to the Standard CGI class.
class CGI 
	# CGI doesn't have a redirect method.  Strange eh?
	# Sets the 302 Moved header to point the url specified in where.
	def redirect( where )
		print header( { 'status' => '302 Moved', 'location' => "#{where}" } )
	end

	# Perhaps not a great place for this, but rfc3339 is an internet standard ....
	# Takes a string with a time encoded according to rfc3339 and returns a Time object.
	def timeforRFC3339( rfc3339 )
		year = rfc3339[ 0..3 ].to_i
		month = rfc3339[ 4..5 ].to_i
		day = rfc3339[ 6..7 ].to_i
		hour = rfc3339[ 9..10 ].to_i
		minute = rfc3339[ 11..12 ].to_i
		second = rfc3339[ 13..14 ].to_i
		return Time.gm( year, month, day, hour, minute, second)
	end
end

# This is the class that does the business.
# To use in your ruby cgi script:
# 	Require 'raven'
# Create a Raven object
# 	raven = Raven.new
# Give Raven some information about your script. Defaults are used if not specified.
# 	raven.return_url = "http://myhost.com/mycgi/myscript.rb
#	raven.description = "My Amazing Application"
#	raven.message = "I need to know it is really you"
# Make sure you have defined a CGI object
#	cgi = CGI.new( 'html4' )
# Try and authenticate the user
# 	authentication = raven.authenticate( cgi )
# What we do next depends on the response:
# 	case authentication
#	when String # Authentication has succeeded
#		user_name = authentication
#	when Integer # Authentication has returned an error
#		error_code = authentication
#	when nil # Authentication wishes to redirect to Raven
#		# DO NOTHING !
#	end
#
# Once the person has been authenticated succesfully this will be recorded
# in a cookie, to eliminate future requests. To delete the cookie:
# 	raven.de_authenticate( cgi )
#
# If you want to insist that Raven interact with the user, either
#	raven.iact = 'yes'
# for it to occur on all authentications, or 
# 	raven.authenticate( cgi, "message explaining interaction", 'yes' )
# to make them interact just this once.
#
class Raven
	
	# The url of the raven service. Defaults to https://raven.cam.ac.uk/auth/authenticate.html
	attr_accessor :raven_url
	# The version of the raven protocol being used.  Defaults to 1
	attr_accessor :raven_version
	# The maximum difference permitted between the clocks on this server and Raven (plus message transmission time) in seconds
	attr_accessor :max_skew
	# The public keys used by the Raven service to sign its messages.  Must be a Hash where Keys are valid Raven
	# Key Ids and the values are objects that duck type to a method like OpenSSL::PKey.verify
	attr_accessor :publickey
	# The default location to look for the public key used by the Raven service.  Assumes this is a text file with an RSA public key.
	DEFAULT_PUBLIC_KEY_FILE = 'pubkey2.txt'
	# The default Raven Key Id.
	DEFAULT_PUBLIC_KEY_ID = '2'

	# The url of this cgi script.  Guesed from the calling user's http headers if not given (which cannot be relied upon)
	attr_accessor :return_url
	# A description of this website provided by Raven to the user
	attr_accessor :description
	# A message as to why authentication is required probided by Raven to the user
	attr_accessor :message 
	# An array of strings of the accepted authentication types.  Defaults to nothing, which means anything that Raven finds acceptable
	attr_accessor :aauth
	# A string containing 'yes' or if we wish to insist that authentication takes place.  Defaults to blank.
	attr_accessor :iact
	# A boolean as to whether we wish to insist that all Raven responses to us be triggered by a request by this script.  
	# If you don't set the return_url explicitly, then this should be true to avoid a security hole.
	# Default is true.
	attr_accessor :match_response_and_request
	# If 'Yes' then Raven will not return a response to this script unless it has a successfull authentication.
	# Note that this script may still return an error code if the time skew is out, the signature is invalid, or the response
	# didn't match a request.
	# Defaults to '' (ie No)
	attr_accessor :fail

	def initialize
		# Put some default values in for now
		@raven_url = 'https://raven.cam.ac.uk/auth/authenticate.html'
		@raven_version = '1'
		@max_skew = 90 # seconds
		@publickey = Hash.new
		begin
			@publickey[ DEFAULT_PUBLIC_KEY_ID ] = OpenSSL::PKey::RSA.new( IO.readlines( DEFAULT_PUBLIC_KEY_FILE ).to_s )
		rescue => err
			$stderr.puts err
			$stderr.puts "Public Key failed to load from #{DEFAULT_PUBLIC_KEY_FILE}"
		end

		@description = 'There is no description for this website'
		@message = 'No reason has been given'
		@aauth = []
		@iact = ""
		@match_response_and_request = true
		@fail = ""
	end

	# Can call this to log off.
	def de_authenticate( cgi )
		CGI::Session.new(cgi).delete
	end
	
	# This is the call to authenticate.  
	def authenticate( cgi, message = @message, iact = @iact )
		# If the application hasn't set the url, then we shall guess it. This will fail if it is running on a different port.
		@return_url ||= "http://#{cgi.server_name}#{cgi.script_name}"
	
		# Open (or start a new) session with the user
		session = CGI::Session.new(cgi)
		
		# Try stages 1 2 and 3 in sequence, returning the first one that is not nil.
		response = check_session( session, iact ) || check_response_from_raven( cgi, session, iact ) || send_request_to_raven( cgi, session, message, iact )
		
		# Close the session 
		session.close

		# Return the response
		return response
	end

	private
	
	def check_session( session, iact )
		# Currently always goes for Raven if interaction is asked for.  Alternative would be to check whether it had been PREVIOUSLY asked for.
		return nil if iact == 'yes'
		
		if session['principal'] && session['expires'] && ( Time.at( session['expires'].to_i ) > Time.now )
			return session['principal']
		else
			return nil
		end
	end
	
	def check_response_from_raven( cgi, session, iact )
		return nil if cgi['WLS-Response'] == ""
		
		wls_response = cgi.params['WLS-Response'].to_s
		ver, status, msg, issue, id, url, principal, auth, sso, life, params, kid, sig = wls_response.split('!')
		
		#Try and restore any stored parameters
		begin 
			cgi.params= YAML::load( session['stored_parameters'] )
		rescue => err
			$stderr.puts err
			$stderr.puts "YAML::load failed.  Possibly no parameters were stored"
		end

		#Check the protocol version
		return 520 unless ver == @raven_version
		
		#Check the url
		return 570 unless url == @return_url
	
		#Check the time skew
		issuetime = cgi.timeforRFC3339( issue )
		skew = issuetime - Time.now
		return 550 unless skew.abs < @max_skew

		#Optionally check that interaction with the user took place
		return 540 if ( iact == 'yes' &&  auth == "" )
		
		#Optionally check that this response matches a request
		if @match_response_and_request
			response_id = CGI.unescape( params )
			request_id = session['request_id']
			$stderr.puts "#{response_id} v #{request_id}"
			return 570 unless request_id == response_id
		end
		
		
		#If we got here, and status is 200, then yield the principal
		if status == '200'
			#Check that the Key Id is one we currently accept
			publickey = @publickey[ CGI.unescape( kid ) ]
			return 560 unless publickey	
			
			#Check the signature
			length_to_drop = -(sig.length + kid.length + 3)
			signedbit = wls_response[ 0 .. length_to_drop]
			return 560 unless publickey.verify( OpenSSL::Digest::SHA1.new, Base64::decode64(sig.tr('-._','+/=')), signedbit)
			
			#Signature ok. So store this person in a session so don't need to repeatedly authenticate.
			session['principal'] = principal
			session['expires'] = Time.now.to_i + life.to_i if life

			# Return the authenticated person
			return principal
		end
		
		#And return the error code if it is something else.
		return status.to_i
		
	end

	def send_request_to_raven( cgi, session, message, iact)
		#Store all the parameters in the session
		session['stored_parameters'] = cgi.params.to_yaml

		#Store a random number in params so we can match this request to later responses
		params = session['request_id'] = rand( 999999 ).to_s
		
		# And off we redirect.
		cgi.redirect("#{@raven_url}?ver=#{CGI.escape(@raven_version)};url=#{CGI.escape(@return_url)};desc=#{CGI.escape(@description)};msg=#{CGI.escape(message)};iact=#{CGI.escape(iact)};aauth=#{CGI.escape(@aauth.join(","))};params=#{CGI.escape(params)};fail=#{CGI.escape(@fail)}")

		# Return nil, so that the application knows not to write any more cgi
		return nil
	end

		
end
