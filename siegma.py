import os
import sys
import json
import copy
import yaml
import argparse
import subprocess
from pyattck import Attck
from pprint import pprint
from rule_file_creator_scripts import es_qs
from helpers.utils import setup_logger, config_file_to_dict, get_slash_set_path


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
	parser.add_argument('-sv', '--sigma_venv', metavar='<sigma_python_venv>', type=str, default='', help='Sigma repository Python virtual environment path. Eg: /path/to/sigma/.venv3.')
	parser.add_argument('-o', '--output', metavar='<output_file>', type=str, default='.output', help='Output file path. Eg: /path/to/output_file.')
	parser.add_argument('-t', '--testing', dest='testing', action='store_true', help='Switch for testing. Default "False". If testing, output file will be created but the rule file will not be installed on SIEM. Eg: -t or --testing.')
	parser.add_argument('-sep', '--sigma_extra_parameters', dest='sigma_extra_parameters', action='store_true', help='Switch for enabling backend options feature of sigma. Default "False". Eg: -sbo or --sigma_extra_parameters.')
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
	logger.debug(args.sigma_venv)
	args.sigma = args.sigma.rstrip('\\')
	args.sigma = args.sigma.rstrip('/')
	args.rule = args.rule.rstrip('\\')
	args.rule = args.rule.rstrip('/')
	args.sigma_venv = args.sigma_venv.rstrip('\\')
	args.sigma_venv = args.sigma_venv.rstrip('/')
	if args.verbosity is not None and not args.verbosity: logger.setLevel(verbosity)
	logger.info('initialize_g_vars() finished successfully...')


def get_sigma_config_from_config(config):
	return config.get('sigma_config')


def get_sigma_path_from_config(config):
	return config.get('path_to_sigma_folder')


def get_sigma_query_conversion_result(sigma, sigma_venv, sigma_config, sigma_query_format, rule, sigma_extra_parameters):
	# if windows, execute these commands
	result = query = command = None
	# if windows machine
	if os.name == 'nt':
		logger.info('Windows powershell command shall be executed...')
		command = 'powershell -nop -c ". {1}\\Scripts\\activate.ps1; python {0}\\tools\\sigmac -c {2} -t {3} {4};"'.format(sigma, sigma_venv, sigma_config, sigma_query_format, rule)
		logger.debug(command)
		result = subprocess.run('powershell -nop -c ". {1}\\Scripts\\activate.ps1; python {0}\\tools\\sigmac -c {2} -t {3} {4};"'.format(sigma, sigma_venv, sigma_config, sigma_query_format, rule), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
		result_out = result.stdout.decode('utf-8')
		result_error = result.stderr.decode('utf-8')
		query = result_out.splitlines()[0]
		logger.debug(query)
		logger.error(result_error)
	# if linux machine
	else:
		logger.info('Linux shell shall be executed...')
		command = ". {1}/bin/activate; python {0}/tools/sigmac -c {2} -t {3} {4};".format(sigma, sigma_venv, sigma_config, sigma_query_format, rule)
		logger.debug('Command:')
		logger.debug(command)
		process = subprocess.Popen(get_slash_set_path(command), stdout=subprocess.PIPE, shell=True)
		proc_stdout = process.communicate()[0].strip().decode('utf-8')
		print(proc_stdout)
		query = proc_stdout.splitlines()[-1]
		logger.info(query)
	return query


def load_yaml_rule_into_json(yj_rule):
	with open(yj_rule) as f:
		yj_rule = json.loads(json.dumps(yaml.load(f)))
	logger.debug(yj_rule)
	return yj_rule


def create_rule_file_for_siem(sigma_query_format, config, credentials, query, yj_rule, output, testing=False):
	rule_file = None
	config_copy = copy.deepcopy(config)
	yj_rule = load_yaml_rule_into_json(yj_rule)
	if sigma_query_format in ['es-qs']:
		rule_file = es_qs.create_rule(config_copy, credentials, query, yj_rule, attack, output, os.path.dirname(os.path.realpath(__file__)), logger, testing=testing)
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


def get_sigma_extra_parameters(sigma_extra_parameters, sigma_params):
	sigma_extra_params = ''
	try:
		if type(sigma_params) == dict and len(sigma_params) > 0:
			for key, value in sigma_params.items():
				if type(value) == list:
					logger.debug('list type params found for key {}...'.format(key))
					
		else: logger.warn('sigma_params are empty in config...')
	except Exception as e:
		logger.error('Exception {} occurred in get_sigma_extra_parameters()...'.format(e))
	return sigma_extra_parameters


def install_rule_files_on_siem(sigma_query_format, credentials, out_file_name):
	if sigma_query_format in ['es-qs']:
		if es_qs.valid_credentials(credentials, logger):
			es_qs.install_rules(os.path.dirname(os.path.realpath(__file__)), credentials, out_file_name, logger)


def main():
	try:
		initialize_g_vars()
		empty_output_file(output=args.output)
		out_file_name = ''
		for idx, rule in enumerate(get_all_rule_files(args.rule)):
			logger.debug('rule iteration {}...'.format(idx))
			query = get_sigma_query_conversion_result(args.sigma, args.sigma_venv, args.sigma_config, args.config.get('sigma_query_format'), rule, get_sigma_extra_parameters(args.sigma_extra_parameters, args.config('sigma_params')))
			out_file_name = create_rule_file_for_siem(args.config.get('sigma_query_format'), args.config.get('settings'), args.config.get('credentials'), query, rule, args.output, testing=args.testing)
			logger.info('Output file name: {}...'.format(out_file_name))
		if not args.testing:
			install_rule_files_on_siem(args.config.get('sigma_query_format'), args.config.get('credentials'), out_file_name)
		else:
			logger.info('No rules installed on SIEM since Testing switch is enabled...')
	except Exception as e:
		logger.error('Exception {} occurred in main of file {}...'.format(e, os.path.basename(__file__)))


# main flow of the program
##########################
main()
##########################
