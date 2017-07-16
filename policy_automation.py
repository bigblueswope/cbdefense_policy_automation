#!/usr/bin/env python

import sys
import csv
import re
import argparse
import logging
import logging.config
import json
import pprint
import collections
try:
	import requests
except ImportError as e:
	print "It appears that you do not have the required Python module 'requests' installed."
	print "Try running the following command to install 'requests'"
	print "	sudo pip install requests --upgrade"
	sys.exit(0)

import components as pc
import functions as functs



pp = pprint.PrettyPrinter(indent=4)
session = requests.Session()


def make_requestHeaders(place):
	host = functs.get_cbd_instance(place)
	user, password = functs.get_username_password(place)
	print "Validating credentials..."
	referer = host + '/ui'
	hostname = host.split('/',3)[-1]
	requestHeaders = { 'Host': hostname, 'Origin': host, 'Referer': referer }
	requestHeaders['X-CSRF-Token'] = functs.login(session, user, password, host, requestHeaders)
	return host, requestHeaders

def apply_changes(policyDescription, groupId, policyName, jsonPolicy, priorityLevel, infile, host, requestHeaders):
	formdata = {"id": groupId,
				"origname": policyName,
				"name": policyName,
				"origdescription": policyDescription,
				"description": policyDescription,
				"priorityLevel": priorityLevel,
				"origpriorityLevel": priorityLevel,
				"adminVersion": False,
				"policy": jsonPolicy}

	if infile:
		with open (infile, 'rU') as f:
			reader = csv.reader(f)
			for row in reader:
				rule_id = formdata['policy']['maxRuleId'] + 1
				rule = {'required': 'false', 'id': rule_id}
			
				app_dict = {}
				app_dict['type'], app_dict['value'] = functs.app_match(row[0])
				if not app_dict['value']:
					adv = row[0].split(': ')[1]
					adv = re.sub('"', '', adv)
					app_dict['value'] = adv
				
				rule['application'] = app_dict.copy()
				rule['operation'] = functs.op_match(row[1])
				if rule['operation'] == 'BYPASS_ALL':
					#force the action to be IGNORE
					rule['action'] = 'IGNORE'
				else:
					#otherwise follow the CSV
					rule['action'] = functs.action_match(row[2])
				
				formdata['policy']['rules'].append(rule.copy())
				formdata['policy']['maxRuleId'] = rule_id
	
	print "Inserting configuration and rules into policy id:  %i" % (groupId)
	logger.info("Inserting configuration and rules into policy id = {0}".format(groupId))

	uri = '/settings/groups/modify'
	functs.web_post(session, uri, formdata, host, requestHeaders)
	
	print "Policy Import completed. Logging out."
	logger.info("Policy import completed. Logging out.")

	uri = '/logout'
	functs.web_get(session, uri, host, requestHeaders)


def import_policy(infile, intype, host, requestHeaders):
	policyName = functs.get_policy_name(infile)
	policyDescription = functs.get_policy_description()
	priorityLevel = functs.get_policy_priority()
	policyPriorityLevel = functs.get_policy_priority_level()
	
	formdata = {"name": policyName,
				"description": policyDescription,
				"priorityLevel": priorityLevel,
				"priority": int(policyPriorityLevel),
				"sourceGroupId": None}

	print "Creating Policy: %s" % (policyName)
	logger.info("Creating policy = {0}".format(policyName))

	uri = '/settings/groups/add'
	response = functs.web_post(session, uri, formdata, host, requestHeaders)

	functs.does_policy_exist(response, policyName)

	groupId = response['addedDeviceGroupId']

	if intype == 'from_csv':
		jsonPolicy = pc.policy_template.copy()
	
	elif intype == 'from_json_memory':
		jsonPolicy = infile
		infile = ''
	
	elif intype == 'from_json_file':
		with open(infile, 'r') as f:
			jsonPolicy = json.load(f)
		infile = ''
	else:
		print "Error:  Import Policy called for an unsupported format."
		logger.error("Error: import_policy function called for an unsupported format. Format = {0}".format(intype))
		sys.exit(1)
	
	apply_changes(policyDescription, groupId, policyName, jsonPolicy, priorityLevel, infile, host, requestHeaders)

def import_certs(infile, host, requestHeaders):
	uri = '/settings/hashentry/add'
	with open (infile, 'rU') as f:
		reader = csv.reader(f)
		for row in reader:
			formdata = {}
			formdata['description'] = row[3]
			formdata['hashListType'] = "WHITE_LIST"
			formdata['reputationOverrideType'] = "CERT"
			formdata['value1'] = row[2]
			formdata['value2'] = row[4]
			
			print "Adding Certificate: %s" % (formdata['description'])
			logger.info("Added Certificate = {0}".format(formdata['description']))
			
			response = functs.web_post(session, uri, formdata, host, requestHeaders)
	
	print "Certificate Import completed. Logging out."
	logger.info("Certificate import completed.  Logging out.")
	
	uri = '/logout'
	functs.web_get(session, uri, host, requestHeaders)	  			


def import_searches(infile, host, requestHeaders):
	#It appears that the UI submits a search and after submitting the search saves the search

	# This first bit of work is to grab the "orgId" which is a part of the info submitted
	#  when the search is saved
	url = host + '/userInfo'
	response = session.get(url, headers=requestHeaders, timeout=30)
	
	if 'currentOrgId' in response.json() and response.json()['currentOrgId'] is not None:
		orgId = json.dumps(response.json()['currentOrgId']).replace('"', '')
	else:
		print "No OrgId found exiting."
		logger.error("No OrgId found. Exiting search import.")
		sys.exit(1)
	
	if 'loginId' in response.json() and response.json()['loginId'] is not None:
		loginId = json.dumps(response.json()['loginId']).replace('"', '')
	else:
		print "No loginId found, exiting."
		logger.error("No loginId found.  Exiting search import.")
		sys.exit(1)
	
	# Setting the Referer header just in case this is why the server didn't work for me.
	requestHeaders['Referer'] = "%s/investigate" % (host)
	
	# Iterate over the contents of the CSV
	#  Field 0 = search box contents
	#  Field 1 = search timeframe
	#  Field 2 = Name of search
	with open (infile, 'rU') as f:
		reader = csv.reader(f)
		for row in reader:
			# contents of the form are taken from /investigate/events/find as seen in chrome dev tools
			formdata = {}
			formdata['searchDefinition'] = {'type': 'INVESTIGATE',
					'maxRows':'20',
					'fromRow': '1',
					'searchWindow': row[1],
					'sortDefinition': {
						'fieldName':'TIME',
						'sortOrder':'DESC'
					},
					'criteria':{
						'QUERY_STRING_TYPE': [row[0]]
					},
					'name': row[2],
					'orgId': orgId
				}
			print "*" * 80
			print formdata
			print "#" * 80
			
			
			print "Adding search: %s" % (row[2])
			logger.info("Adding search {0}".format(row[2]))

			uri = '/searchdefs/save'
			response = functs.web_post(session, uri, formdata, host, requestHeaders)
			
			print response.headers
			print response.content
	
	print "Search Import completed. Logging out."
	logger.info("Search import completed. Logging out.")
	
	uri = '/logout'
	functs.web_get(session, uri, host, requestHeaders)

	
def export_policy(exp_type, host, requestHeaders):
	uri = '/settings/groups/list'
	response = functs.web_get(session, uri, host, requestHeaders)
	
	if response['success']:
		# creating a list of the policies from the target org
		menu_number = 0
		policies = collections.OrderedDict()
		pol_names = []

		for entry in response['entries']:
			policies[entry['name']] = {'orgId': entry['orgId'], 'id': entry['id']}
			pol_names.append(entry['name'])
		
		print "Policies Available for Export:"
		for key in policies.keys():
			print '%i) %s' % (menu_number, key)
			menu_number += 1
	
		pol_id = int(raw_input("Choose the number for your SOURCE Policy: "))
		
		if pol_id < menu_number:
			pol_name = pol_names[int(pol_id)]
			
			print "SOURCE Policy Name: %s" % (pol_name)
			logger.info("Source Policy Name = {0}".format(pol_name))
			
			groupId = policies[pol_name]['id']
			
			print 'SOURCE Policy ID: %i' % (groupId)
			logger.info("Source Policy ID = {0}".format(groupId))
			
		else:
			print "Invalid SOURCE Policy choice received.  Rerun the script and retry."
			logger.info("Tool exited because user input Number = {0} but Max Policy Number was {1}".format(pol_id, menu_number))
			sys.exit(1)
	
	uri = '/settings/policy/%i/details' % (groupId)
	response = functs.web_get(session, uri, host, requestHeaders)
	
	if response['success']:
		jsonResponse = json.dumps(response['policy'], indent=4, sort_keys=True)
		if exp_type == 'to_json_file':
			if not args.output:
				print "No Output File Specified."
				outfile = raw_input("Specify output filename or just press 'Enter' to output to '%s.json': " % (pol_name))
				if outfile == '':
					outfile = pol_name + '.json'
			else:
				outfile = args.output
			with open(outfile, 'w') as outf:
				outf.write(jsonResponse)
			
			logger.info("Exported policy '{0}' to file '{1}'".format(pol_name, outfile))
		
		elif exp_type == 'to_json_memory':
			policyDescription = response['description']
			groupId = response['id']
			policyName = response['name']
			jsonPolicy = response['policy']
			priorityLevel = response['priorityLevel']
			return policyDescription, groupId, policyName, jsonPolicy, priorityLevel
		
		else:
			print "Export type not specified.  No data exported."
			logger.info("Exited the tool because the policy output type was not 'to_json_file' or 'to_json_memory'")
			sys.exit(1)

def edit_policy(policyDescription, groupId, policyName, jsonPolicy, priorityLevel, infile, host, requestHeaders):

	#write original policy for safety's sake
	fo_name = "%s_orig.json" % (str(groupId))
	with open(fo_name, 'w') as fo:
		json.dump(jsonPolicy, fo, indent=4, sort_keys=True)
	logger.info("Backed up {0} to file {1} prior to applying edits".format(policyName, fo_name))
	
	apply_changes(policyDescription, groupId, policyName, jsonPolicy, priorityLevel, infile, host, requestHeaders)


def main():
	functs.check_request_version()
	
	if args.action:
		logger.info("action = {0}".format(args.action))
	
	if args.action == 'export_json':
		print "\n##### Begin Policy Export #####"
		host, requestHeaders = make_requestHeaders('SOURCE')
		logger.info("server = {0}".format( host))
		
		export_policy('to_json_file', host, requestHeaders)
		
	elif args.action == 'import_csv':
		if not args.input:
			args.input = raw_input("No Input file specified.\nWhat CSV file contains the rules to import?: ")
		print "Using %s as rule source" % (args.input)
		
		print "\n##### Begin Policy Import #####"
		host, requestHeaders = make_requestHeaders('DESTINATION')
		logger.info("server = {0}".format(host))
		logger.info("CSV Source = {0}".format(args.input))
		
		import_policy(args.input, 'from_csv', host, requestHeaders)
	
	elif args.action == 'import_json':
		if not args.input:
			args.input = raw_input("No Input file specified.\nWhat JSON file contains the policy to import?: ")
		print "Using %s as rule source" % (args.input)
		
		print "\n##### Begin Policy Import #####"
		host, requestHeaders = make_requestHeaders('DESTINATION')
		logger.info("server = {0}".format(host))
		logger.info("JSON source = {0}".format(args.input))
		
		import_policy(args.input, 'from_json_file', host, requestHeaders)
	
	elif args.action == 'import_certs':
		if not args.input:
			args.input = raw_input("No Input file specified.\nWhat CSV file contains the certs to import?: ")
		print "Using %s as cert source" % (args.input)
		
		print "\n##### Begin Certificate Import #####"
		host, requestHeaders = make_requestHeaders('DESTINATION')
		logger.info("server = {0}".format(host))
		logger.info("Cert CSV = {0}".format(args.input))
		
		import_certs(args.input, host, requestHeaders)
	
	elif args.action == 'import_searches':
		if not args.input:
			args.input = raw_input("No Input file specified.\nWhat CSV file contains the queries to import?: ")
		print "Using %s as query source" % (args.input)
		
		print "\n##### Begin Search Import #####"
		host, requestHeaders = make_requestHeaders('DESTINATION')
		logger.info("server = {0}".format(host))
		logger.info("Search CSV = {0}".format(args.input))
		
		import_searches(args.input, host, requestHeaders)
	
	elif args.action == 'transfer':
		print "\n##### Begin Policy Export #####"
		host, requestHeaders = make_requestHeaders('SOURCE')
		logger.info("Source server = {0}".format(host))
		
		policyDescription, groupId, policyName, jsonPolicy, priorityLevel = export_policy('to_json_memory', host, requestHeaders)
		#jsonPolicy is the only variable used for transfer, but define all because edit_policy needs them
		logger.info("Exported Policy Name = {0}".format(policyName))
		
		print "\n##### Begin Policy Import #####"
		host, requestHeaders = make_requestHeaders('DESTINATION')
		logger.info("Destination server = {0}".format(host))
		
		import_policy(jsonPolicy, 'from_json_memory', host, requestHeaders)
	
	elif args.action == 'edit_policy':
		if not args.input:
			args.input = raw_input("No Input file specified.\nWhat CSV file contains the rules to import?: ")
		print "Using %s as rule source" % (args.input)
		infile = args.input

		print "\n##### Begin Policy Edit #####"
		host, requestHeaders = make_requestHeaders('DESTINATION')
		logger.info("server = {0}".format(host))
		logger.info("Edits CSV = {0}".format(args.input))
		
		policyDescription, groupId, policyName, jsonPolicy, priorityLevel = export_policy('to_json_memory', host, requestHeaders)
		logger.info("Edited Policy Name = {0}".format(policyName))

		edit_policy(policyDescription, groupId, policyName, jsonPolicy, priorityLevel, infile, host, requestHeaders)

	else:
		print "Error: action was not one of 'export_json/import_csv/import_json/transfer/import_certs'."
		print "Please rerun the script providing a correct action argument"



if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-a", "--action", help="Action to be taken.  Valid values: import_csv,import_json,export_json,transfer,import_certs, edit_policy", required=True)
	parser.add_argument("-i", "--input", help="File containing rules or policy to import.")
	parser.add_argument("-o", "--output", help="File to which to write policy JSON. Just in case you wish to verify the JSON.")
	args = parser.parse_args()
	
	logging.config.fileConfig('logging.conf')
	logger = logging.getLogger(__name__)
	logger.info("Policy Automation Tool Started")
	
	main()


#Tests we should run:
#	export_json
#		with -o
#		without -o
#			accept pol name as outfile
#			not accept pol name as outfile
#	import_csv
#		with -i
#			accept filename as pol name
#			not accept filename as pol name
#		without -i
#			accept filename as pol name
#			not accept filename as pol name
#	import_json
#		with -i
#			accept filename as pol name
#			not accept filename as pol name
#		without -i
#			accept filename as pol name
#			not accept filename as pol name
#	import_certs
#		with -i
#		without -i
#	transfer
#		same server
#			same org
#				keep dst pol name same: should fail
#				change dst pol name
#			diff org
#				keep dst pol name same
#				change dst pol name
#		diff servers
#			keep dst pol name same
#			change dst pol name
#	edit_policy
#		with -i
#		without -i
