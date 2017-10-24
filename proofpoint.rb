# Copyright 2017 Emmanuel Torquato.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'restclient'
require 'json'
require 'time'

module ProofPoint

	APP_NAME = "proofpoint"
	VERSION = "0.0.1"
	AUTHOR = "Emmanuel Torquato"
	RESULT_FIELDS = [:result, :recipient, :sender, :threatsinfomap, :classification, :description, :startdate, :actors, :action, :families, :malware, :campaignmembers, :techniques, :type, :subtype, :what, :md5, :sha256, 
					:url, :domain, :key, :value, :rule, :blacklisted, :threat, :threattime, :threatstatus, :threats, :threatid, :threaturl, :campaignid, :id, :name, :scope, :display, :evidence, :malicious, :time, :platforms,
					:forensics, :offset, :size, :host, :cnames, :ips, :nameservers, :nameserverslist, :path, :signatureid, :ip, :port, :httpstatus, :spamscore, :phishscore, :messagetime, :impostorscore, :cluster, :subject,
					:quarantinefolder, :quarantinerule, :policyroutes, :modulesrun, :messagesize, :headerfrom, :headerreplyto, :fromaddress, :ccaddresses, :replytoaddress, :toaddresses, :xmailer, :messageparts, :disposition,
					:filename, :sandboxstatus, :ocontenttype, :contenttype, :completelyrewritten, :qid, :guid, :senderip, :malwarescore, :messageid, :note, :messagesdelivered, :messagesblocked]
	DEFAULTENVIRONMENTID = "1"
	PP_API = "https://tap-api-v2.proofpoint.com"
	
	# Queries the API using RestClient and parses response
	#
	# @param url [String] URL endpoint to send the request to
	# @param user [String] ProofPoint Service Principal for authentication
	# @param password [String] ProofPoint Api Key for authentication
	# @param params [Hash] Hash of HTTP params
	# @param proxy [Boolean] use proxy from local env or not
	#
	# @return [JSON] Parsed response
	def self.query_api(url, user, password, params)
	
		resource = RestClient::Resource.new(url, :user => user, :password => password, :accept => 'application/json')
		begin
			if !params.nil?
				response = resource.get(:params => params)
			else
				response = resource.get()
			end
		rescue => e
			#puts e
			response = e.response
		end
		
		self.parse_response response
	end
	
	# Parses the response or raises an exception accordingly.
	#
	# @param response The response from RestClient
	#
	# @return [JSON] Parsed response
	def self.parse_response(response)
		#puts "Parse Response"
		begin
			case response.code
				when 429
					raise "Too Many Requests. The user has made too many requests over the past 24 hours and has been throttled."
				when 403
					raise "Forbidden. The user is authenticated for the service but is not authorized to access data for the given customer."
				when 400
					raise "Bad Request. The request is missing a mandatory parameter, a parameter contains data which is incorrectly formatted, or the API doesn't have enough information to determine the identity of the customer."
				when 401
					raise "Unauthorized. There is no authorization information included in the request, the authorization information is incorrect, or the user is not authorized."
				when 404
					raise "Not Found. The Campaign ID or Threat ID does not exist."
				when 200
					begin
						JSON.parse(response)
					rescue
						response
					end
				when 500
					nil
				else
					raise "Unknown Server error. (#{response.code})"
			end
		end
	end
	
	# Module for Querying the Campaign API functionalities
	# https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Campaign_API
	module PPCampaign
		CAMPAIGN_BASE_URL		= ProofPoint::PP_API + "/v2/campaign"
		
		def PPCampaign.get(user, password, id)
			if user == nil
				raise "You must provide a ProofPoint Service Principal"
			end
			if password == nil
				raise "You must provide a ProofPoint Secret API Key"
			end
			if id == nil
				raise "You must provide should an id"
			end

			ProofPoint.query_api(CAMPAIGN_BASE_URL + "/" + id, user, password, nil)
		end
		
		# A wrapper class with methods for handling specific data from campaign data
		class PPCampaignParser
			RESULT_FIELDS = ProofPoint::RESULT_FIELDS
			attr_accessor :result
			
			def initialize results
				if results == nil or results.empty?
					return
				end
				@result = Hash.new
				@result[:name] = results('name')
				@result[:description] = results('description')
				@result[:startdate] = Time.iso8601(results('startDate'))
				if results('actors').length > 0
					actors = Array.new
					results('actors').each do |actor|
						resp = Hash.new
						resp[:id] = actor('id')
						resp[:name] = actor('name')
						actors.push(resp)
					end
					@result[:actors] = actors
				end
				if results('families').length > 0
					families = Array.new
					results('families').each do |family|
						resp = Hash.new
						resp[:id] = family('id')
						resp[:name] = family('name')
						families.push(resp)
					end
					@result[:families] = families
				end
				if results('malware').length > 0
					malwares = Array.new
					results('malware').each do |malware|
						resp = Hash.new
						resp[:id] = malware('id')
						resp[:name] = malware('name')
						malwares.push(resp)
					end
					@result[:malware] = malwares
				end
				if results('techniques').length > 0
					techniques = Array.new
					results('techniques').each do |technique|
						resp = Hash.new
						resp[:id] = technique('id')
						resp[:name] = technique('name')
						techniques.push(resp)
					end
					@result[:techniques] = techniques
				end
				if results('campaignMembers').length > 0
					campaignmembers = Array.new
					results('campaignMembers').each do |member|
						resp = Hash.new
						resp[:id] = member('id')
						resp[:threat] = member('threat')
						resp[:threatstatus] = member('threatStatus')
						resp[:type] = member('type')
						resp[:subtype] = member('subType')
						resp[:threattime] = Time.iso8601(member('threatTime'))
						campaignmembers.push(resp)
					end
					@result[:campaignmembers] = campaignmembers
				end
			end
			
			# output all malicious url detected in campaign
			#
			# @return [Array] of malicious url
			def getallurl()
				if !@result.nil?
					if @result[:campaignmembers].length > 0
						url = Array.new
						result[:campaignmembers].each do |campaign|
							if campaign[:type] == 'url'
								if campaign[:subtype] == 'COMPLETE_URL'
									url.push(campaign[:threat])
								end
							end
						end
						return url.uniq! unless url.length == 0
					end
				end
			end
			
			# output all malicious hash detected in campaign
			#
			# @return [Array] of malicious hash
			def getallattachment()
				if !@result.nil?
					if @result[:campaignmembers].length > 0
						attachment = Array.new
						result[:campaignmembers].each do |campaign|
							if campaign[:type] == 'attachment'
								if campaign[:subtype] == 'ATTACHMENT'
									attachment.push(campaign[:threat])
								end
							end
						end
						return attachment.uniq! unless attachment.length == 0
					end
				end
			end
			
		end		
	end
	
	# Module for Querying the Forensics API functionalities
	# https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Forensics_API
	module PPForensics
		FORENSICS_BASE_URL		= ProofPoint::PP_API + "/v2/forensics"
		
		def PPForensics.get(user, password, id, idtype = 'threatId', **args)
			if user == nil
				raise "You must provide a ProofPoint Service Principal"
			end
			if password == nil
				raise "You must provide a ProofPoint Secret API Key"
			end
			if id == nil
				raise "You must provide should an id"
			end
			begin
				case idtype
					when 'threatId'
						params = {
							'threatId': id
						}
						ProofPoint.query_api(FORENSICS_BASE_URL, user, password, params.merge!(args))
					when 'campaignId'
						params = {
							'campaignId': id
						}
						ProofPoint.query_api(FORENSICS_BASE_URL, user, password, params.merge!(args))
					else
						raise "Unkwnown ID Type, should use\'threatId\' or \'campaignId\'"
				end
			end
		end
		
		# A wrapper class with methods for handling specific data from forensics results		
		class PPForensicsParser
		
			RESULT_FIELDS = ProofPoint::RESULT_FIELDS
			attr_accessor :result
			
			def initialize results
				if results == nil or results.empty?
					return
				end
				if !results.has_key?('reports')
					return
				end
				if results['reports'].length > 0
					@result = Array.new
					results['reports'].each do |report|
						rep = Hash.new
						rep[:name] = report['name']
						rep[:scope] = report['scope']
						rep[:type] = report['type']
						rep[:threatid] = report['id']
						rep[:threatstatus] = report['threatStatus']
						if report.has_key?('forensics')
							forensics = Array.new
							report['forensics'].each do |forensic|
								forens = Hash.new
								forens[:type] = forensic['type']
								forens[:display] = forensic['display']
								forens[:malicious] = forensic['malicious']
								forens[:time] = forensic['time']
								forens[:note] = forensic['note'] if forensic.has_key?('note')
								if forensic.has_key?('what')
									iocs = Hash.new
									iocs[:url] = forensic['what']['url'] if forensic['what'].has_key?('url')
									iocs[:action] = forensic['what']['action'] if forensic['what'].has_key?('action')
									iocs[:domain] = forensic['what']['domain'] if forensic['what'].has_key?('domain')
									iocs[:key] = forensic['what']['key'] if forensic['what'].has_key?('key')
									iocs[:value] = forensic['what']['value'] if forensic['what'].has_key?('value')
									iocs[:rule] = forensic['what']['rule'] if forensic['what'].has_key?('rule')
									iocs[:md5] = forensic['what']['md5'] if forensic['what'].has_key?('md5')
									iocs[:sha256] = forensic['what']['sha256'] if forensic['what'].has_key?('sha256')
									iocs[:blacklisted] = forensic['what']['blacklisted'] if forensic['what'].has_key?('blacklisted')
									iocs[:offset] = forensic['what']['offset'] if forensic['what'].has_key?('offset')
									iocs[:size] = forensic['what']['size'] if forensic['what'].has_key?('size')
									iocs[:host] = forensic['what']['host'] if forensic['what'].has_key?('host')
									iocs[:cnames] = forensic['what']['cnames'] if forensic['what'].has_key?('cnames')
									iocs[:ips] = forensic['what']['ips'] if forensic['what'].has_key?('ips')
									iocs[:nameservers] = forensic['what']['nameservers'] if forensic['what'].has_key?('nameservers')
									iocs[:nameserverslist] = forensic['what']['nameserversList'] if forensic['what'].has_key?('nameserversList')
									iocs[:path] = forensic['what']['path'] if forensic['what'].has_key?('path')
									iocs[:signatureid] = forensic['what']['signatureId'] if forensic['what'].has_key?('signatureId')
									iocs[:ip] = forensic['what']['ip'] if forensic['what'].has_key?('ip')
									iocs[:port] = forensic['what']['port'] if forensic['what'].has_key?('port')
									iocs[:type] = forensic['what']['type'] if forensic['what'].has_key?('type')
									iocs[:httpstatus] = forensic['what']['httpStatus'] if forensic['what'].has_key?('httpStatus')
									forens[:what] = iocs
								end
								forens[:platforms] = forensic['platforms']
								forensics.push(forens)
							end
							rep[:forensics] = forensics
						end
						@result.push(rep)
					end
				else
					return
				end
			end
			
			# output display data for active threat which are malicious
			#
			# @return [Array] of {Hash} with 'type' and 'display' as keys
			def get_active_display()
				if !@result.nil?
					iocs = Array.new
					@result.each do |elem|
						if elem[:threatstatus] == 'active'
							elem[:forensics].each do |forens|
								iocs.push({"type": forens[:type], "display": forens[:display]}) if forens[:malicious]
							end
						end
					end
					return iocs if iocs.length > 0
				end
			end
			
			# Check if one reports has a type attachment
			#
			# @return boolean or nil if result is nil
			def is_type_attachment?()
				if !@result.nil?
					@result.each do |elem|
						if elem[:type] == 'attachment'
							return true
						end
					end
					return false
				end
			end
			
			# Check if one reports has a type url
			#
			# @return boolean or nil if result is nil
			def is_type_url?()
				if !@result.nil?
					@result.each do |elem|
						if elem[:type] == 'url'
							return true
						end
					end
					return false
				end
			end
			
			# Output all "what" field data when threat is active
			#
			# @return [Array] of {Hash} with 'type' and 'what' as keys for malicious indicators
			def get_active_indicator()
				if !@result.nil?
					indicators = Array.new
					@result.each do |elem|
						if elem[:threatstatus] == 'active'
							elem[:forensics].each do |forens|
								indicators.push({"type": forens[:type], "malicious": forens[:malicious], "what": forens[:what]})
							end
						end
					end
					return indicators if indicators.length > 0
				end
			end

			# Output all "what" field data when threat is active and ioc is malicious
			#
			# @return [Array] of {Hash} with 'type' and 'what' as keys for malicious indicators
			def get_active_malicious_indicator()
				if !@result.nil?
					indicators = Array.new
					@result.each do |elem|
						if elem[:threatstatus] == 'active'
							elem[:forensics].each do |forens|
								indicators.push({"type": forens[:type], "malicious": forens[:malicious], "what": forens[:what]}) if forens[:malicious]
							end
						end
					end
					return indicators if indicators.length > 0
				end
			end
			
			# Output all "what" field data when threat is active
			#
			# @return [Array] of {Hash} with 'type' and 'what' as keys for malicious indicators
			def get_indicator()
				if !@result.nil?
					indicators = Array.new
					@result.each do |elem|
						elem[:forensics].each do |forens|
							indicators.push({"type": forens[:type], "malicious": forens[:malicious], "what": forens[:what]})
						end
					end
					return indicators if indicators.length > 0
				end
			end
			
			# Output all "what" field data independently of threat status and when ioc is malicious
			#
			# @return [Array] of {Hash} with 'type' and 'what' as keys for malicious indicators
			def get_malicious_indicator()
				if !@result.nil?
					indicators = Array.new
					@result.each do |elem|
						elem[:forensics].each do |forens|
							indicators.push({"type": forens[:type], "malicious": forens[:malicious], "what": forens[:what]}) if forens[:malicious]
						end
					end
					return indicators if indicators.length > 0
				end
			end
					
		end	
	end
						
				
			
	
	# Module for Querying the SIEM API functionalities
	# Actually only messages blocked, messages delivered SIEM API integration
	# https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API
	
	module PPSiem
		SIEM_BASE_URL			= ProofPoint::PP_API + "/v2/siem"
		CLICK_BLOCKED_URL		= SIEM_BASE_URL + "/clicks/bloked"
		CLICK_PERMITTED_URL		= SIEM_BASE_URL + "/clicks/permitted"
		MESSAGES_BLOCKED_URL	= SIEM_BASE_URL + "/messages/blocked"
		MESSAGES_DELIVERED_URL	= SIEM_BASE_URL + "/messages/delivered"
		ISSUES_URL				= SIEM_BASE_URL + "/issues"
		ALL_URL					= SIEM_BASE_URL + "/all"
		
		# Query ProofPoint API for delivered messages
		#
		# @param [String] service principal for authentication
		# @param [String] secret api key for authentication
		# @param [String] timeframe type, should be one of 'interval', 'sinceSeconds', 'sinceTime'
		#
		# @return [JSON] Parsed response
		
		def PPSiem.messages_delivered(user, password, timeframetype='sinceSeconds', timeframe='3600', **args)
			if user == nil
				raise "You must provide a ProofPoint Service Principal"
			end
			if password == nil
				raise "You must provide a ProofPoint Secret API Key"
			end
			begin
				case timeframetype
					when 'interval'
						interval = timeframe.split('/')
						if interval.length != 2
							raise "Invalid interval. must be like \'2017-05-01T12:00:00Z/2017-05-01T13:00:00Z\'"
						end
						begin
							# Check only for iso8601 format, not handle format as 'PT30M'
							Time.iso8601(interval[0])
							Time.iso8601(interval[1])
						rescue ArgumentError => e
							raise "Invalid Time format given. You should use ISO8601"
						end
						params = {
							'format': 'json',
							'interval': timeframe
						}
						
						ProofPoint.query_api(MESSAGES_DELIVERED_URL, user, password, params.merge!(args))
					
					when 'sinceSeconds'
						if timeframe.to_i == 0
							raise "Wrong value. should be time in seconds less than 3600"
						end
						if timeframe.to_i > 3600
							raise "Time in seconds should be less than 3600."
						end
						params = {
							'format': 'json',
							'sinceSeconds': timeframe
						}
						ProofPoint.query_api(MESSAGES_DELIVERED_URL, user, password, params)
					
					when 'sinceTime'
						begin
							Time.iso8601(timeframe)
						rescue ArgumentError => e
							raise "Invalid Time format given. You should use ISO8601"
						end
						params = {
							'format': 'json',
							'sinceTime': timeframe
						}
						ProofPoint.query_api(MESSAGES_DELIVERED_URL, user, password, params.merge!(args))
					else
						raise "Wrong parameter. You should use one of \'interval\', \'sinceSeconds\', \'sinceTime\'"
				end
			end
		end
		
		# Query ProofPoint API for blocked messages
		#
		# @param [string] service principal for authentication
		# @param [string] secret api key for authentication
		# @param [string] timeframe type, should be one of 'interval', 'sinceSeconds', 'sinceTime'
		#
		# @return [JSON] Parsed response
		
		def PPSiem.messages_blocked(user, password, timeframetype='sinceSeconds', timeframe='3600', **args)
			if user == nil
				raise "You must provide a ProofPoint Service Principal"
			end
			if password == nil
				raise "You must provide a ProofPoint Secret API Key"
			end
			begin
				case timeframetype
					when 'interval'
						interval = timeframe.split('/')
						if interval.length != 2
							raise "Invalid interval. must be like \'2017-05-01T12:00:00Z/2017-05-01T13:00:00Z\'"
						end
						begin
							# Check only for iso8601 format, not handle format as 'PT30M'
							Time.iso8601(interval[0])
							Time.iso8601(interval[1])
						rescue ArgumentError => e
							raise "Invalid Time format given. You should use ISO8601"
						end
						params = {
							'format': 'json',
							'interval': timeframe
						}
						ProofPoint.query_api(MESSAGES_BLOCKED_URL, user, password, params.merge!(args))
					
					when 'sinceSeconds'
						#puts "debugs #{timeframetype}, #{timeframe}"
						if timeframe.to_i == 0
							raise "Wrong value. should be time in seconds less than 3600"
						end
						if timeframe.to_i > 3600
							raise "Time in seconds should be less than 3600."
						end
						params = {
							'format': 'json',
							'sinceSeconds': timeframe
						}
						ProofPoint.query_api(MESSAGES_BLOCKED_URL, user, password, params)
					
					when 'sinceTime'
						begin
							Time.iso8601(timeframe)
						rescue ArgumentError => e
							raise "Invalid Time format given. You should use ISO8601"
						end
						params = {
							'format': 'json',
							'sinceTime': timeframe
						}
						ProofPoint.query_api(MESSAGES_BLOCKED_URL, user, password, params.merge!(args))
					else
						raise "Wrong parameter. You should use one of \'interval\', \'sinceSeconds\', \'sinceTime\'"
				end
			end
		end
		
		# Query ProofPoint API issues when click allowed or message delivered with threats
		#
		# @param [string] service principal for authentication
		# @param [string] secret api key for authentication
		# @param [string] timeframe type, should be one of 'interval', 'sinceSeconds', 'sinceTime'
		#
		# @return [JSON] Parsed response
		
		def PPSiem.issues(user, password, timeframetype='sinceSeconds', timeframe='3600', **args)
			if user == nil
				raise "You must provide a ProofPoint Service Principal"
			end
			if password == nil
				raise "You must provide a ProofPoint Secret API Key"
			end
			begin
				case timeframetype
					when 'interval'
						interval = timeframe.split('/')
						if interval.length != 2
							raise "Invalid interval. must be like \'2017-05-01T12:00:00Z/2017-05-01T13:00:00Z\'"
						end
						begin
							# Check only for iso8601 format, not handle format as 'PT30M'
							Time.iso8601(interval[0])
							Time.iso8601(interval[1])
						rescue ArgumentError => e
							raise "Invalid Time format given. You should use ISO8601"
						end
						params = {
							'format': 'json',
							'interval': timeframe
						}
						
						ProofPoint.query_api(ISSUES_URL, user, password, params.merge!(args))
					
					when 'sinceSeconds'
						if timeframe.to_i == 0
							raise "Wrong value. should be time in seconds less than 3600"
						end
						if timeframe.to_i > 3600
							raise "Time in seconds should be less than 3600."
						end
						params = {
							'format': 'json',
							'sinceSeconds': timeframe
						}
						ProofPoint.query_api(ISSUES_URL, user, password, params)
					
					when 'sinceTime'
						begin
							Time.iso8601(timeframe)
						rescue ArgumentError => e
							raise "Invalid Time format given. You should use ISO8601"
						end
						params = {
							'format': 'json',
							'sinceTime': timeframe
						}
						ProofPoint.query_api(ISSUES_URL, user, password, params.merge!(args))
					else
						raise "Wrong parameter. You should use one of \'interval\', \'sinceSeconds\', \'sinceTime\'"
				end
			end
		end
		
		# Query ProofPoint API all clicks and messages known with threats
		#
		# @param [string] service principal for authentication
		# @param [string] secret api key for authentication
		# @param [string] timeframe type, should be one of 'interval', 'sinceSeconds', 'sinceTime'
		#
		# @return [JSON] Parsed response
		
		def PPSiem.all(user, password, timeframetype='sinceSeconds', timeframe='3600', **args)
			if user == nil
				raise "You must provide a ProofPoint Service Principal"
			end
			if password == nil
				raise "You must provide a ProofPoint Secret API Key"
			end
			begin
				case timeframetype
					when 'interval'
						interval = timeframe.split('/')
						if interval.length != 2
							raise "Invalid interval. must be like \'2017-05-01T12:00:00Z/2017-05-01T13:00:00Z\'"
						end
						begin
							# Check only for iso8601 format, not handle format as 'PT30M'
							Time.iso8601(interval[0])
							Time.iso8601(interval[1])
						rescue ArgumentError => e
							raise "Invalid Time format given. You should use ISO8601"
						end
						params = {
							'format': 'json',
							'interval': timeframe
						}
						
						ProofPoint.query_api(ALL_URL, user, password, params.merge!(args))
					
					when 'sinceSeconds'
						if timeframe.to_i <= 0
							raise "Wrong value. should be time in seconds less than 3600"
						end
						if timeframe.to_i > 3600
							raise "Time in seconds should be less than 3600."
						end
						params = {
							'format': 'json',
							'sinceSeconds': timeframe
						}
						ProofPoint.query_api(ALL_URL, user, password, params)
					
					when 'sinceTime'
						begin
							Time.iso8601(timeframe)
						rescue ArgumentError => e
							raise "Invalid Time format given. You should use ISO8601"
						end
						params = {
							'format': 'json',
							'sinceTime': timeframe
						}
						ProofPoint.query_api(ALL_URL, user, password, params.merge!(args))
					else
						raise "Wrong parameter. You should use one of \'interval\', \'sinceSeconds\', \'sinceTime\'"
				end
			end
		end
				
		
		# A wrapper class with methods for handling specific data from messages like sender, recipients and threats		
		class PPSiemMessagesParser
		
			RESULT_FIELDS = ProofPoint::RESULT_FIELDS
			attr_accessor :result
			
			def initialize results
				if results == nil or results.empty?
					return
				end
				if !results.has_key?('queryEndTime')
					return
				end
				msg_types = Array.new
				if results.has_key?('messagesDelivered')
					#msg_types.push(:messagesdelivered)
					msg_types.push('messagesDelivered')
				end
				if results.has_key?('messagesBlocked')
					#msg_types.push(:messagesblocked)
					msg_types.push('messagesBlocked')
				end
				if msg_types.length > 0
					@result = Hash.new
					msg_types.each do |msg_type|
						messagedetails = Array.new
						results[msg_type].each do |report|
							res = Hash.new
							res[:recipient] = report['recipient']
							res[:sender] = report['sender']
							res[:spamscore] = report['spamScore']
							res[:phishscore] = report['phishScore']
							res[:impostorscore] = report['impostorScore'].to_i
							res[:malwarescore] = report['malwareScore']
							res[:cluster] = report['cluster']
							res[:subject] = report['subject']
							res[:quarantinefolder] = report['quarantineFolder']
							res[:quarantinerule] = report['quarantineRule']
							res[:messagesize] = report['messageSize']
							res[:messagetime] = Time.iso8601(report['messageTime'])
							res[:headerfrom] = report['headerFrom']
							res[:headerreplyto] = report['headerReplyto']
							res[:xmailer] = report['xmailer']
							res[:completelyrewritten] = report['completelyRewritten']
							res[:qid] = report['QID']
							res[:guid] = report['GUID']
							res[:senderip] = report['senderIP']
							res[:messageid] = report['messageID']
							res[:policyroutes] = report['policyRoutes']
							res[:modulesrun] = report['modulesRun']
							res[:fromaddress] = report['fromAddress']
							res[:ccaddresses] = report['ccAddresses']
							res[:replytoaddress] = report['replyToAddress']
							res[:toaddresses] = report['toAddresses']
							if report['threatsInfoMap'].length > 0
								threats = Array.new
								report['threatsInfoMap'].each do |threatinfo|
									threat = Hash.new
									threat[:threatid] = threatinfo['threatID']
									threat[:threatstatus] = threatinfo['threatStatus']
									threat[:threaturl] = threatinfo['threatUrl']
									threat[:threattime] = Time.iso8601(threatinfo['threatTime'])
									threat[:campaignid] = threatinfo['campaignID']
									threat[:classification] = threatinfo['classification']
									threat[:type] = threatinfo['threatType']
									threat[:threat] = threatinfo['threat']
									threats.push(threat)
								end
								res[:threatsinfomap] = threats
							end
							if !report['messageParts'].nil?
								if report['messageParts'].length > 0
									messageparts = Array.new
									report['messageParts'].each do |elem|
										messagepart = Hash.new
										messagepart[:disposition] = elem['disposition']
										messagepart[:sha256] = elem['sha256']
										messagepart[:md5] = elem['md5']
										messagepart[:filename] = elem['filename']
										messagepart[:sandboxstatus] = elem['sandboxStatus']
										messagepart[:ocontenttype] = elem['oContentType']
										messagepart[:contenttype] = elem['contentType']
										messageparts.push(messagepart)
									end
									res[:messageparts] = messageparts
								end
							end
							messagedetails.push(res)
						end
						case msg_type
							when 'messagesBlocked'
								@result[:messagesblocked] = messagedetails
							when 'messagesDelivered'
								@result[:messagesdelivered] = messagedetails
						end
					end
				else
					return
				end
			end
			

			# Outputs senders for delivered message
			#
			# @return [Array]
			def get_delivered_sender()
				if !@result.nil?
					if @result.has_key?(:messagesdelivered)
						if @result[:messagesdelivered].length > 0
							senders = Array.new
							@result[:messagesdelivered].each do |elem|
								senders.push(elem[:sender]) unless elem[:sender].length == 0
							end
							return senders if senders.length > 0
						end
					end
				end
			end
			
			# Outputs senders for blocked message
			#
			# @return [Array]
			def get_blocked_sender()
				if !@result.nil?
					if @result.has_key?(:messagesblocked)
						if @result[:messagesblocked].length > 0
							senders = Array.new
							@result[:messagesblocked].each do |elem|
								senders.push(elem[:sender]) unless elem[:sender].length == 0
							end
							return senders if senders.length > 0
						end
					end
				end
			end
			
			
			# Outputs recipients for delivered malicious email
			#
			# @return [Array]
			def get_delivered_recipient()
				if !@result.nil?
					if @result.has_key?(:messagesdelivered)
						if @result[:messagesdelivered].length > 0
							recipients = Array.new
							@result[:messagesdelivered].each do |elem|
								recipients.push(elem[:recipient]) unless elem[:recipient].length == 0
							end
							return recipients if recipients.length > 0
						end
					end
				end
			end
			
			# Outputs recipients for blocked malicious email
			#
			# @return [Array]
			def get_blocked_recipient()
				if !@result.nil?
					if @result.has_key?(:messagesblocked)
						if @result[:messagesblocked].length > 0
							recipients = Array.new
							@result[:messagesblocked].each do |elem|
								recipients.push(elem[:recipient]) unless elem[:recipient].length == 0
							end
							return recipients if recipients.length > 0
						end
					end
				end
			end
			

			# Outputs all delivered threats
			#
			# @return [Array] of threats {Hash}
			def get_delivered_threat()
				if !@result.nil?
					if @result.has_key?(:messagesdelivered)
						if @result[:messagesdelivered].length > 0
							threats = Array.new
							@result[:messagesdelivered].each do |item|
								item[:threatsinfomap].each do |elem|
									threats.push(elem)
								end
							end
							return threats if threats.length > 0
						end
					end
				end
			end
			
			# Outputs all blocked threats
			#
			# @return [Array] of threats {Hash}
			def get_blocked_threat()
				if !@result.nil?
					if @result.has_key?(:messagesblocked)
						if @result[:messagesblocked].length > 0
							threats = Array.new
							@result[:messagesblocked].each do |item|
								item[:threatsinfomap].each do |elem|
									threats.push(elem)
								end
							end
							return threats if threats.length > 0
						end
					end
				end
			end
			
			# Outputs delivered spam threats
			#
			# @return [Array] of Spam threats {Hash}
			def get_delivered_spam()
				if !@result.nil?
					if @result.has_key?(:messagesdelivered)
						if @result[:messagesdelivered].length > 0
							spams = Array.new
							@result[:messagesdelivered].each do |item|
								item[:threatsinfomap].each do |elem|
									spams.push(elem) if elem[:classification] == 'spam'
								end
							end
							return spams if spams.length > 0
						end
					end
				end
			end
			
			# Outputs blocked spam threats
			#
			# @return [Array] of Spam threats {Hash}
			def get_blocked_spam()
				if !@result.nil?
					if @result.has_key?(:messagesblocked)
						if @result[:messagesblocked].length > 0
							spams = Array.new
							@result[:messagesblocked].each do |item|
								item[:threatsinfomap].each do |elem|
									spams.push(elem) if elem[:classification] == 'spam'
								end
							end
							return spams if spams.length > 0
						end
					end
				end
			end		
			
			# Outputs delivered malware threats
			#
			# @return [Array] of malware threats {Hash}
			def get_delivered_malware()
				if !@result.nil?
					if @result.has_key?(:messagesdelivered)
						if @result[:messagesdelivered].length > 0
							malwares = Array.new
							@result[:messagesdelivered].each do |item|
								item[:threatsinfomap].each do |elem|
									malwares.push(elem) if elem[:classification] == 'malware'
								end
							end
							return malwares if malwares.length > 0
						end
					end
				end
			end
			
			# Outputs blocked malware threats
			#
			# @return [Array] of malware threats {Hash}
			def get_blocked_malware()
				if !@result.nil?
					if @result.has_key?(:messagesblocked)
						if @result[:messagesblocked].length > 0
							malwares = Array.new
							@result[:messagesblocked].each do |item|
								item[:threatsinfomap].each do |elem|
									malwares.push(elem) if elem[:classification] == 'malware'
								end
							end
							return malwares if malwares.length > 0
						end
					end
				end
			end
			

			# Outputs delivered phish threats
			#
			# @return [Array] of phish threats {Hash}
			def get_delivered_phish()
				if !@result.nil?
					if @result.has_key?(:messagesdelivered)
						if @result[:messagesdelivered].length > 0
							phishes = Array.new
							@result[:messagesdelivered].each do |item|
								item[:threatsinfomap].each do |elem|
									phishes.push(elem) if elem[:classification] == 'phish'
								end
							end
							return phishes if phishes.length > 0
						end
					end
				end
			end
			
			# Outputs delivered phish threats
			#
			# @return [Array] of phish threats {Hash}
			def get_blocked_phish()
				if !@result.nil?
					if @result.has_key?(:messagesblocked)
						if @result[:messagesblocked].length > 0
							phishes = Array.new
							@result[:messagesblocked].each do |item|
								item[:threatsinfomap].each do |elem|
									phishes.push(elem) if elem[:classification] == 'phish'
								end
							end
							return phishes if phishes.length > 0
						end
					end
				end
			end
			
			# Outputs campaignId for delivered messages
			#
			# @return [Array] of campaign id String
			def get_delivered_campaign()
				if !@result.nil?
					if @result.has_key?(:messagesdelivered)
						if @result[:messagesdelivered].length > 0
							campaigns = Array.new
							@result[:messagesdelivered].each do |item|
								item[:threatsinfomap].each do |elem|
									campaigns.push(elem[:campaignid]) unless elem[:campaignid].nil?
								end
							end
							campaigns.compact!
							campaigns.uniq!
							return campaigns if campaigns.length > 0
						end
					end
				end
			end
			
			# Outputs campaignId for blocked messages
			#
			# @return [Array] of campaign id String
			def get_blocked_campaign()
				if !@result.nil?
					if @result.has_key?(:messagesblocked)
						if @result[:messagesblocked].length > 0
							campaigns = Array.new
							@result[:messagesblocked].each do |item|
								item[:threatsinfomap].each do |elem|
									campaigns.push(elem[:campaignid]) unless elem[:campaignid].nil?
								end
							end
							campaigns.compact!
							campaigns.uniq!
							return campaigns if campaigns.length > 0
						end
					end
				end
			end
			
			# Ouput to JSON
			#
			# @return [String] JSON representation of the result
			def to_json()
				if !@result.nil?
					#JSON::pretty_generate(@result.map{|entry| { :message => entry } })
					JSON::pretty_generate(@result)
				end
			end
			
			# Return Array for delivered Threat with scores for spam, phish, impostor, malware
			#
			# @return[Array] of {Hash}
			def get_delivered_score()
				if !@result.nil?
					if @result.has_key?(:messagesdelivered)
						if @result[:messagesdelivered].length > 0
							scores = Array.new
							@result[:messagesdelivered].each do |item|
								score = Hash.new
								score[:guid] = item[:guid]
								score[:sender] = item[:sender]
								score[:headerfrom] = item[:headerfrom]
								score[:subject] = item[:subject]
								if item[:threatsinfomap].length > 0
									threatsId = Array.new
									item[:threatsinfomap].each do |threat|
										threatsId.push(threat[:threatid])
									end
									score[:threatid] = threatsId
								end
								score[:spamscore] = item[:spamscore]
								score[:phishscore] = item[:phishscore]
								score[:impostorscore] = item[:impostorscore]
								score[:malwarescore] = item[:malwarescore]
								scores.push(score)
							end
							return scores if scores.length > 0
						end
					end
				end
			end
			
			# Return Array for blocked Threat with scores for spam, phish, impostor, malware
			#
			# @return[Array] of {Hash}
			def get_blocked_score()
				if !@result.nil?
					if @result.has_key?(:messagesblocked)
						if @result[:messagesblocked].length > 0
							scores = Array.new
							@result[:messagesblocked].each do |item|
								score = Hash.new
								score[:guid] = item[:guid]
								score[:sender] = item[:sender]
								score[:headerfrom] = item[:headerfrom]
								score[:subject] = item[:subject]
								if item[:threatsinfomap].length > 0
									threatsId = Array.new
									item[:threatsinfomap].each do |threat|
										threatsId.push(threat[:threatid])
									end
									score[:threatid] = threatsId
								end
								score[:spamscore] = item[:spamscore]
								score[:phishscore] = item[:phishscore]
								score[:impostorscore] = item[:impostorscore]
								score[:malwarescore] = item[:malwarescore]
								scores.push(score)
							end
							return scores if scores.length > 0
						end
					end
				end
			end
		end
	end
end
