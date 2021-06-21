import os
import sys
import json
import copy
import yaml
import argparse
import subprocess
import collections
from pyattck import Attck
from pprint import pprint
from rule_file_creator_scripts import es_qs, ala_rule
from helpers.utils import setup_logger, config_file_to_dict, get_slash_set_path, get_slashes


# global vars
#############
logger = None
args = None
slash = '/'
attack = Attck()
#############


def empty_output_file(output='.output.ndjson'):
	with open(output, "w") as outfile: pass
	logger.info('Output file {} has been created and emptied...'.format(output))
	return output


def setup_args():
	parser = argparse.ArgumentParser(os.path.basename(__file__))
	parser.add_argument('-c', '--config', metavar='<config_file_path>', type=str, default='config/.config.json', help='Config file path. Eg: /path/to/config.json')
	parser.add_argument('-r', '--rule', metavar='<rule_file_path> / <rule_folder_path>', type=str, help='Rule file / folder path. Eg: /path/to/rule/file.yml or /path/to/rules/folder.')
	parser.add_argument('-s', '--sigma', metavar='<sigma_directory>', type=str, default='', help='Sigma repository path. Eg: /path/to/sigma.')
	parser.add_argument('-sc', '--sigma_config', metavar='<sigma_config_file>', type=str, default='', help='Sigma config file path. Eg: /path/to/sigma/tools/config/ecs-cloudtrail.yml.')
	parser.add_argument('-o', '--output', metavar='<output_file>', type=str, default='.output', help='Output file path. Eg: /path/to/output_file.')
	parser.add_argument('-co', '--config_override', metavar='<config_override>', type=str, default='', help='Values that can be used to override config. Eg: settings.rule_id="some_id",settings.custom_field="custom_value",custom_field="custom_value",settings.author=none,credentials.kibana_url="www.example.com",sigma_query_format="es-qs".')
	parser.add_argument('-t', '--testing', dest='testing', action='store_true', help='Switch for testing. Default "False". If testing, output file will be created but the rule file will not be installed on SIEM. Eg: -t or --testing.')
	parser.add_argument('-sep', '--sigma_extra_parameters', dest='sigma_extra_parameters', action='store_true', help='Switch for enabling backend options feature of sigma. If this switch is passed here, sigma_params values from config file will be read and used by the script. Default "False". Eg: -sep or --sigma_extra_parameters.')
	parser.add_argument('-v', '--verbosity', metavar='<verbosity_level>', type=str, default='DEBUG', help='Execution verbosity level. Eg: SUCCESS|WARN|INFO|DEBUG.')
	logger.info('Arguments parsed successfully...')
	return parser.parse_args()


def force_exit(msg, exit=1):
	if exit == 1:
		logger.error(msg)
	else:
		logger.info(msg)
	sys.exit(exit)


def initialize_g_vars():
	global logger, args
	logger = setup_logger()
	args = setup_args()
	# get siem config
	args.config = config_file_to_dict(filename=args.config)
	pprint(args.config)
	# get sigma folder path
	args.sigma = args.sigma if not (args.sigma is None or args.sigma == '') else force_exit('Sigma folder path is required...', exit=1)
	logger.debug(args.sigma)
	# get sigma config file path
	args.sigma_config = args.sigma_config if not (args.sigma_config is None or args.sigma_config == '') else force_exit('Sigma Config is required...', exit=1)
	logger.debug(args.sigma_config)
	args.sigma = args.sigma.rstrip('\\')
	args.sigma = args.sigma.rstrip('/')
	args.rule = args.rule.rstrip('\\')
	args.rule = args.rule.rstrip('/')
	logger.setLevel(args.verbosity)
	logger.info('initialize_g_vars() finished successfully...')


def get_sigma_config_from_config(config):
	return config.get('sigma_config')


def get_sigma_path_from_config(config):
	return config.get('path_to_sigma_folder')


def get_sigma_query_conversion_result(sigma, sigma_config, sigma_query_format, rule, sigma_extra_parameters):
	# if windows, execute these commands
	result = query = command = None
	return_status = 0
	try:
		# if windows machine
		if os.name == 'nt':
			logger.info('Windows powershell command shall be executed...')
			command = 'powershell -nop -c "pipenv run python {0}\\tools\\sigmac -c {1} -t {2} {4} {3};"'.format(sigma, sigma_config, sigma_query_format, rule, sigma_extra_parameters)
			logger.debug(command)
			result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
			result_out = result.stdout.decode('utf-8')
			result_error = result.stderr.decode('utf-8')
			# if error code var is not empty, then set return status to 1
			if result.returncode != 0: return_status = 1
			query = result_out.splitlines()[0]
			logger.debug(query)
			logger.error(result_error)
		# if linux machine
		else:
			logger.info('Linux shell shall be executed...')
			command = "pipenv run python {0}/tools/sigmac -c {1} -t {2} {4} {3};".format(sigma, sigma_config, sigma_query_format, rule, sigma_extra_parameters)
			logger.debug('Command:')
			logger.debug(command)
			process = subprocess.Popen(get_slash_set_path(command), stdout=subprocess.PIPE, shell=True)
			proc_stdout = process.communicate()[0].strip().decode('utf-8')
			result_error = process.returncode
			# if error code var is not empty, then set return status to 1
			if result_error != 0: return_status = 1
			print(proc_stdout)
			query = proc_stdout.splitlines()[-1]
			logger.info(query)
	except Exception as e:
		logger.error('Exception {} occurred in get_sigma_query_conversion_result()...'.format(e))
		return_status = 1
	return return_status, query


def load_yaml_rule_into_json(yj_rule):
	with open(yj_rule) as f:
		yj_rule = json.loads(json.dumps(yaml.load(f)))
	logger.debug(yj_rule)
	return yj_rule


def create_rule_file_for_siem(siegma_config, notes_folder, sigma_query_format, sigma_config, config, credentials, query, yj_rule, output, testing=False):
	rule_file = None
	config_copy = copy.deepcopy(config)
	yj_rule = load_yaml_rule_into_json(yj_rule)
	sigma_config = load_yaml_rule_into_json(sigma_config)
	if sigma_query_format in ['es-qs']:
		rule_file = es_qs.create_rule(siegma_config, notes_folder, config_copy, sigma_config, credentials, query, yj_rule, attack, output, os.path.dirname(os.path.realpath(__file__)), logger, testing=testing)
	elif sigma_query_format in ['ala-rule']:
		rule_file = ala_rule.create_rule(siegma_config, notes_folder, config_copy, sigma_config, credentials, json.loads(query), yj_rule, attack, output, os.path.dirname(os.path.realpath(__file__)), logger, testing=testing)
	else: pass
	return rule_file


def getListOfYMLFiles(dirName):
	# create a list of file and sub directories 
	# names in the given directory 
	listOfFile = os.listdir(dirName)
	allFiles = list()
	# Iterate over all the entries
	for entry in listOfFile:
		# Create full path
		fullPath = os.path.join(dirName, entry)
		# If entry is a directory then get the list of files in this directory 
		if os.path.isdir(fullPath):
			allFiles = allFiles + getListOfYMLFiles(fullPath)
		else:
			if fullPath.lower().endswith('.yml'):
				allFiles.append(fullPath)
	return allFiles


def get_all_rule_files(rule_path):
	ret = []
	is_dir = os.path.isdir(rule_path)
	if is_dir: 
		ret = getListOfYMLFiles(rule_path)
	else:
		ret.append(rule_path)
	logger.info('Printing {} rules identified: '.format(len(ret)))
	pprint(ret)
	logger.info('get_all_rule_files() finished successfully...')
	return ret


def get_sigma_extra_parameters(sigma_extra_parameters, sigma_params, yj_rule):
	sigma_extra_params = ''
	already_done = False
	try:
		logger.debug('Checking sigma params from rule file...')
		if (not already_done) and yj_rule is not None and yj_rule != '' and type(yj_rule) == dict and len(yj_rule) > 0 and 'sigma' in yj_rule:
			logger.debug('sigma params from rule file will be used...')
			already_done = True
			for key, value in yj_rule.get('sigma').items():
				pprint(value)
				if type(value) == dict:
					for k2, v2 in value.items():
						if type(v2) == list:
							sigma_extra_params += f'--{key} {k2}=' + ','.join(v2) + ' '
						if type(v2) == str:
							if v2 == "": 
								v2 = "\"\""
								print("sep empty string...")
							sigma_extra_params += f'--{key} {k2}={v2} '
							print("sep string...")
						if type(v2) == bool:
							sigma_extra_params += f'--{key} {k2}={v2} '
		logger.debug('Checking sigma_params from config...')
		if (not already_done) and type(sigma_params) == dict and len(sigma_params) > 0:
			logger.debug('sigma_params from config will be used...')
			for key, value in sigma_params.items():
				if type(value) == list:
					# ignore sigma params with empty lists
					if value == [""]: continue
					logger.debug('list type params found for key {}...'.format(key))
					for item in value:
						sigma_extra_params += '{} {}  '.format(key, item)
				elif type(value) == str:
					logger.debug('str type params found for key {}...'.format(key))
					sigma_extra_params += '{} {}  '.format(key, value)
				else: logger.error('Unhandled type params found for key {} and type {}...'.format(key, type(value)))
		else: logger.warn('sigma_params are empty in config...')
	except Exception as e:
		logger.error('Exception {} occurred in get_sigma_extra_parameters()...'.format(e))
	logger.info('Final sigma_extra_params: {}'.format(sigma_extra_params))
	return sigma_extra_params


def install_rule_files_on_siem(sigma_query_format, credentials, out_file_name, rule):
	return_status = 0
	if sigma_query_format in ['es-qs']:
		if es_qs.valid_credentials(credentials, logger):
			return_status, query = es_qs.install_rules(os.path.dirname(os.path.realpath(__file__)), credentials, out_file_name, logger)
		else:
			return_status = 1
	elif sigma_query_format in ['ala-rule']:
		if ala_rule.valid_credentials(credentials, logger):
			return_status = ala_rule.install_rules(os.path.dirname(os.path.realpath(__file__)), credentials, out_file_name, load_yaml_rule_into_json(rule), logger)
		else:
			return_status = 1
	return return_status


def get_dict_from_dot_separated_string(ret, len_dlist, dlist, value):
	try:
		logger.debug(f'len(dlist) - len_dlist: {len(dlist) - len_dlist}')
		logger.debug('start ret:')
		pprint(ret)
		if len_dlist == 1:
			ret[dlist[len(dlist) - len_dlist]] = value
		elif len_dlist > 0:
			ret[dlist[len(dlist) - len_dlist]] = {}
			logger.debug('elif ret:')
			pprint(ret)
			ret[dlist[len(dlist) - len_dlist]] = get_dict_from_dot_separated_string(ret[dlist[len(dlist) - len_dlist]], len_dlist - 1, dlist, value)
		else: pass
	except Exception as e:
		logger.error(f'Exception {e} occurred in get_dict_from_dot_separated_string()...')
	logger.debug('end ret:')
	pprint(ret)
	return ret


def parse_config_override(config_override):
	ret = {}
	for pairs in config_override.split(','):
		p_split = pairs.split('=')
		logger.debug('p_split: {}'.format(p_split))
		k = p_split[0]
		v = p_split[1]
		k_split = k.split('.')
		ret = update_dict(ret, get_dict_from_dot_separated_string({}, len(k_split), k_split, v))
		logger.debug('String to dict:')
		pprint(ret)
	logger.info('String to dict:')
	pprint(ret)
	return ret


def update_dict(orig_dict, new_dict):
	for key, val in new_dict.items():
		if isinstance(val, collections.Mapping):
			tmp = update_dict(orig_dict.get(key, { }), val)
			orig_dict[key] = tmp
		elif isinstance(val, list):
			orig_dict[key] = (orig_dict.get(key, []) + val)
		else:
			orig_dict[key] = new_dict[key]
	return orig_dict


def update_config(config_override, config):
	ret = config
	try:
		if config_override == "": return ret
		dict_config_override = parse_config_override(config_override)
		ret = update_dict(ret, dict_config_override)
		logger.info('Updated config:')
		pprint(ret)
	except Exception as e:
		logger.error('Exception {} occurred in update_config()...'.format(e))
	return ret


def check_rules_compliance(rules, return_status):
	rules_are_compliant = True
	result_out = None
	result_error = None
	result = None
	logger.info('Following command shall be executed...')
	# command = 'pipenv run python {2}{0}helpers{0}check_if_compliant.py -p {2}{1}'.format(get_slashes(), rules, os.path.abspath(os.getcwd()))
	# command = 'pipenv run python helpers{0}check_if_compliant.py -p {1}'.format(get_slashes(), rules, os.path.abspath(os.getcwd()))
	# if windows machine
	if os.name == 'nt':
		command = 'pipenv run python helpers{0}check_if_compliant.py -p {1}'.format(get_slashes(), rules, os.path.abspath(os.getcwd()))
		logger.debug('Command:')
		logger.debug(command)
		result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
		result_out = result.stdout.decode('utf-8')
		result_error = result.stderr.decode('utf-8')
		# for i in result_out.splitlines():
		# 	logger.error(i)
		# if error code var is not empty, then set return status to 1
	# if linux machine
	else:
		logger.info('Linux shell shall be executed...')
		command = 'pipenv run python helpers{0}check_if_compliant.py -p {1}'.format(get_slashes(), rules, os.path.abspath(os.getcwd()))
		logger.debug('Command:')
		logger.debug(command)
		result = subprocess.Popen(get_slash_set_path(command), stdout=subprocess.PIPE, shell=True)
		result_out = result.communicate()[0].strip().decode('utf-8')
		# result_error = process.returncode
		# if error code var is not empty, then set return status to 1
		# if result_error != 0: return_status = 1
		# print(proc_stdout)
		# query = proc_stdout.splitlines()[-1]
		# logger.info(query)
	
	for i in result_out.splitlines():
		logger.error(i)
	if result.returncode != 0: 
		rules_are_compliant = False
		return_status = 1
	return return_status, rules_are_compliant


def quit_script_with_error_if_failed(status):
	# if the command did not return status 0, consider it to be ended in error and therefore, exit the script with bash return code of 1
	if status != 0:
		logger.error('Ending script with error code: {}'.format(status))
		sys.exit(1)


def main():
	try:
		initialize_g_vars()
		empty_output_file(output=args.output)
		out_file_name = ''
		return_status = 0

		# rule compliance check
		logger.info('Checking if rule is in a siegma convertible format...')
		return_status, rules_are_compliant = check_rules_compliance(args.rule, return_status)
		if return_status != 0 or not rules_are_compliant: 
			logger.error('Some of the rules are not in the format that is considered convertible by SIEGMA. Exting with error...')
			quit_script_with_error_if_failed(return_status)
		########################

		for idx, rule in enumerate(get_all_rule_files(args.rule)):
			logger.debug('rule iteration {}...'.format(idx))
			return_status, query = get_sigma_query_conversion_result(args.sigma, args.sigma_config, args.config.get('sigma_query_format'), rule, get_sigma_extra_parameters(args.sigma_extra_parameters, args.config.get('sigma_params'), load_yaml_rule_into_json(rule)))
			if args.config_override != "":
				# if config override switch has values then update config
				args.config = update_config(args.config_override, args.config)
			out_file_name = create_rule_file_for_siem(args.config, args.config.get('notes_folder'), args.config.get('sigma_query_format'), args.sigma_config, args.config.get('settings'), args.config.get('credentials'), query, rule, args.output, testing=args.testing)
			logger.info('Output file name: {}...'.format(out_file_name))
			quit_script_with_error_if_failed(return_status)
			# backends that only support single rule installation at a time
			if (not args.testing) and (args.config.get('sigma_query_format') == 'ala-rule'):
				return_status = install_rule_files_on_siem(args.config.get('sigma_query_format'), args.config.get('credentials'), out_file_name, rule)
				quit_script_with_error_if_failed(return_status)
			else:
				logger.info('No rules installed on SIEM since Testing switch is enabled...')
		quit_script_with_error_if_failed(return_status)
		# ignore code section for backend targets that only support single rule installation at a time
		if (not ((args.config.get('sigma_query_format') == 'ala-rule'))):
			# backends that support bulk/multiple rules installation at the same time
			if (not args.testing) and (args.config.get('sigma_query_format') == 'es-qs'):
				return_status = install_rule_files_on_siem(args.config.get('sigma_query_format'), args.config.get('credentials'), out_file_name)
				quit_script_with_error_if_failed(return_status)
			else:
				logger.info('No rules installed on SIEM since Testing switch is enabled...')
			quit_script_with_error_if_failed(return_status)
	except Exception as e:
		logger.error('Exception {} occurred in main of file {}...'.format(e, os.path.basename(__file__)))
		quit_script_with_error_if_failed(1)


# main flow of the program
##########################
main()
##########################