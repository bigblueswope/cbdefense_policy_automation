This is a python tool to allow one to easily:
1.  Import a CSV full of Cb Defense rules to a policy in a CbD instance.
2.  Import a JSON file containing an entire Cb Defense policy
3.  Export the contents of a Cb Defense policy to a JSON file.
4.  Import certificates from a CSV.
5.  Transfer a policy from one Cb Defense organization to another.
6.  Edit an existing policy to add rules ("Blocking and Isolation" or Permissions) 

The tool requires one to have a recent version of the Python library 'requests' installed.
	To install 'requests' try the following command:
		sudo pip install requests --upgrade

If you try to use pip and are told "sudo: pip: command not found" install pip using:
	sudo easy_install pip

The tool is comprised of 3 Python files
policy_automation.py  components.py  framework.py

policy_automation.py is the script we will run, it will import the other two files when it runs.

To execute the script:
python policy_automation.py -a <action_to_be_taken>
or
./policy_automation.py -a <action_to_be_taken>


For help:
python policy_automation.py -h

The script has one mandatory argument "-a" or "--action".

The action argument tells the script which function you wish to perform.

The valid actions are:
	import_csv
	import_json
	import_certs
	export_json
	transfer
	edit_policy

The script supports 2 optional arguments as well:
	-i or --input
	-o or --output

The input argument can be used when performing the input actions.

The output argument can be used when performing the export_json action.

If the optional arguments are not provided on the command line, you will be prompted for the information when the script runs.


Acknowledgements:  Patrick Upatham deserves the bulk of the credit for this tool.  He did all the heavy lifting reverse engineering the policy pages of the Cb Defense UI and wrote the first iterations of each of these functions.  Thank you Patrick!  Pass this man some Kudos points!!!!!

If you have problems running this script reach out to BJ Swope bj@carbonblack.com
