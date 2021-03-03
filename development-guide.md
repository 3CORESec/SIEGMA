# Development & Contribution Notes

This page provides developers with the information required to develop support for additional products or make contributions to this project.

## How to contribute (Developers adding support for more SIEMs & platforms)

* Define the configuration for a given SIEM in:
  * An already created folder under [config](config). See [elastic](config/elastic) for reference.
  * Or create a new folder under [config](config) along with the configuration file and corresponding README. See [elastic](config/elastic) for reference.
* Setup Sigma repository.
* Setup SIEGMA repository.
* Under [rule_file_creator_scripts](rule_file_creator_scripts) folder, add a script by the name of the format that you want to support. For example: [es_qs.py](rule_file_creator_scripts/es_qs.py). This script shall contain all the heavy lifting for conversions. See [es_qs.py](rule_file_creator_scripts/es_qs.py) for reference.
  * 3 main functions inside the [es_qs.py](rule_file_creator_scripts/es_qs.py) get called from [siegma.py](siegma.py) and performs all the tasks related to rule file creation.
    * Function 1 - create_rule_file: This function will take in Sigma rule and configuration as input and prepare the rule file.
    * Function 2 - validate_credentials: This function will take in credentials from the configuration and confirm if the credentials are valid or not.
    * Function 3 - install_rule: This function will upload and install the final rule file on the SIEM/Product.
* At the top of [siegma.py](siegma.py), import your newly created script file.
* Go to create_rule_file_for_siem() in [siegma.py](siegma.py). Add an if/else and point it to the function in your new_format.py.
* Go to main() in [siegma.py](siegma.py) and update it to point to the correct installation and validation functions for the newly created rule format script.

## Folder Hierarchy
* **[config](config)**: Folder that contains sample and production configurations so rule file creation can take place.
  * **[elastic](config/elastic)**: Folder that contains Elastic SIEM configuration files.
* **[rule_file_creator_scripts](rule_file_creator_scripts)**: Folder that contains individual scripts that handle the heavy lifting for different formats.
* **[helpers](helpers)**: Folder containing helper scripts & binaries for siegma.py.
