from tools.LogHandler import LogHandler, logging_levels
from tools.FileTools import FileTools
from tools.DirectoryTools import DirectoryTools
from tools.SigmaUtils import SigmaRule, get_sigma_configuration
from backends.Backends import Backends
import argparse
import os
from backends import all_backends
import traceback

def setup_args() -> argparse.Namespace:
    """
        Setup the command line arguments
    """

    parser = argparse.ArgumentParser(os.path.basename(__file__))
    parser.add_argument("-c", "--config", required=True, dest="config", help="Config file path. Eg: /path/to/config.json")
    parser.add_argument("-b", "--backend",  choices=Backends._member_names_, required=True, dest="backend", help=f"SIEM backend to perform the conversion. Eg: {'|'.join(Backends._member_names_)}")
    parser.add_argument("--api", dest="api", action="store_true", default=False, help="Create a rule in the SIEM using the API.")
    parser.add_argument('-p', '--path', type=str, required=True, help='Rule file / folder path. This should be either the absolute path from root folder or should be relative to sigma, NOT siegma. Eg: /path/to/rule/file.yml or /path/to/rules/folder.')
    parser.add_argument("-sc", "--sigma_config", dest="sigma_config_file", type=str, help="Sigma config file path. Eg: /path/to/sigma/tools/config/ecs-cloudtrail.yml.", required=True)
    parser.add_argument("-o", "--output", dest="output_file", type=str, help="Output file path. Eg: /path/to/output_file.", default=".output.ndjson")
    parser.add_argument("-v", "--verbosity", dest="verbosity_level", choices=logging_levels, type=str, default="INFO", help=f"Execution verbosity level. Eg: {'|'.join(logging_levels)}")
    parser.add_argument("-lf", "--log_file", dest="log_file", type=str, default=".output.log", help="File to save the logs infos.")

    return parser.parse_args()


def main():
    # Setup arguments
    args = setup_args()

    # Create logger instance
    logger = LogHandler(log_file_name=args.log_file, level=args.verbosity_level).setup_logger()

    logger.debug("Loading the configuration files.")
    siem_config = FileTools.load_json_file(file_path=args.config)

    sigma_config = get_sigma_configuration(args.sigma_config_file)
    logger.debug("Configuration files has been loaded.")

    logger.debug("Loading backend rule convertor.")
    backend = Backends.get_backend(args.backend)
    logger.info(f"{backend.name} backend has been loaded.")

    logger.debug(f"Loading {backend.name} convertor")
    rule_convertor = all_backends[backend.name](siem_config)

    if not FileTools.check_if_is_a_file(args.path):
        logger.info("Loading rules files")
        files = DirectoryTools.get_all_files_basename(args.path)
        dir_path = args.path

    else:
        logger.info("Loading rule file")
        files = [FileTools.get_file_basename(args.path)]
        dir_path = FileTools.get_dirname(args.path)

    for file in files:
        try:
            file_path = FileTools.file_path(dir_path, file)
            logger.debug(f"Analyzing rule file {file_path}")

            logger.debug("Creating SigmaRule object.")
            sigma_rule_object = SigmaRule(file_path=file_path, sigma_config=sigma_config)

            logger.debug("Getting rule content.")
            rule_content = sigma_rule_object.get_yml_file_content()

            logger.info(f"Find the rule {rule_content[0].title}")

            logger.debug("Checking rule sintaxe.")
            sigma_rule_object.check_rule_sintaxe(rule_content)

            logger.debug("Getting rule query.")
            query = rule_convertor.convert(rule_content, backend.value)

            logger.debug("Creating rule.")
            elastic_rule = rule_convertor.create_rule(rule_content[0], query)

            logger.debug("Saving rule to a file.")
            rule_convertor.write_rule(f"output\{args.output_file}", elastic_rule)
            logger.info(f"The rule has been saved in the {args.output_file} file.")

            if args.api:
                logger.info(f"Creating rule in {backend.name} via API.")

                if rule_convertor.create_rule_by_api(
                    rule=elastic_rule,
                    siem_url=siem_config["credentials"]["siem_url"],
                    username=siem_config["credentials"]["username"],
                    _passwd=siem_config["credentials"]["password"],
                    apikey=siem_config["credentials"]["apikey"]
                ):
                    logger.info(f"The rule {rule_content[0].title} has been created.")

        except Exception as e:
            logger.error(f"Error during the conversion process of the rule {rule_content[0].title}")
            logger.error(e)
            if args.verbosity_level == "DEBUG":
                traceback.print_exc()

if __name__ == "__main__":
    main()
