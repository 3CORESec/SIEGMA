import os
import json
import logging
import colorlog


# Global Vars
color = {
	"green": "#61ff33",
	"yellow": "#ecff33",
	"red": "#D00000"
}
#############


def create_log_file(log_file_name):
	with open(log_file_name, 'w') as o: pass


def get_slash_set_path(path):
	try:
		slash = '/'
		if path and path != '':
			if os.name == 'nt':
				slash = '\\'
				path = path.replace('/', slash)
			else:
				path = path.replace('\\', slash)
	except Exception as e:
		print(f"Exception {e} occurred in get_slash_set_path() for path {path}...")
	print(f"get_slash_set_path() finished successfully for path {path}...")
	return path


def get_slashes():
    ret = '\\'
    if os.name != 'nt': 
        ret = '/'
        print('Non-windows machine...')
    else:
        print('Windows machine...')
    print('Returning {}...'.format(ret))
    return ret


def setup_logger(log_fmt="%(log_color)s%(asctime)s:%(levelname)s:%(message)s", log_file_name=".output.log", level='DEBUG'):

	# a new log file is created each time.
	# no space issues are caused.
	create_log_file(log_file_name)

	formatter = colorlog.ColoredFormatter(
		log_fmt,
		datefmt='%DT%H:%M:%SZ'
	)

	logger = logging.getLogger()

	handler2 = logging.FileHandler(log_file_name)
	handler = logging.StreamHandler()
	handler.setFormatter(formatter)
	logger.addHandler(handler)
	logger.addHandler(handler2)
	logger.setLevel(level)

	return logger


def config_file_to_dict(filename='config/.sample-config.json'):
	config_dict = {}
	with open(filename) as json_file: config_dict = json.load(json_file)
	return config_dict