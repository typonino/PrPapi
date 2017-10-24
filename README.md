# ProofPoint API Ruby Module
A ruby module for interacting with ProofPoint's private API 

Proofpoint provides access to his customers to following ProofPoint APIs:
* SIEM
* Campaign
* Forensics

ProofPoint API description can be find [here](https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation)

## Requirements
* ruby 2.3+
* json
* rest-client
* private ProofPoint API keys and Service Principal

## Installation
Copy the module file in your ruby module path folder

## Limitation
Actual version supports only email analyzed by ProofPoint and not Url.

## API Usage

### SIEM API example
```require 'proofpoint'

SERVICE_PRINCIPAL = "your service principal"
SECRET = "your secret key"

# Get all threats blocked or delivered from PP SIEM API for the last 5 minutes
allrawthreats = ProofPoint::PPSiem.all(SERVICE_PRINCIPAL, SECRET, 'sinceSeconds', '300')


# Parse returned data by using a wrapped object
allthreats = ProofPoint::PPSiem::PPSiemMessagesParser.new(allrawthreats) if !allrawthreats.nil?	


# Apply specific methods for interesting data and get back result to an Array
if !allthreats.nil?

	# Get all delivered threats in an Array
	delivered_threats = allthreats.get_delivered_threat
	
	# Get all blocked threats in an Array
	blocked_threats = allthreats.get_blocked_threat
	
	# Get only delivered Malware threat in an Array
	delivered_malwares = allthreats.get_delivered_malware
	
	# Get score for delivered messages in an Array
	msg_blocked_scores = allthreats.get_blocked_score
	
	# Get score for blocked messages in an Array
	msg_delivered_scores = allthreats.get_delivered_score
	
end
```

### Forensics API example
```require 'proofpoint'

SERVICE_PRINCIPAL = "your service principal"
SECRET = "your secret key"

if ARGV.length != 1
	puts "Please provide a threatId for checking indicators"
	exit!
end

# Get additional informations from a threatId by querying PP Forensics API
indicators = ProofPoint::PPForensics.get(SERVICE_PRINCIPAL, SECRET, ARGV[0])

# wrapp object
parsedindicators = ProofPoint::PPForensics::PPForensicsParser.new(indicators) if !indicators.nil?

# Get malicious indicators details in an array
maliciousiocs = parsedindicators.get_malicious_indicator if !parsedindicators.nil?
```
