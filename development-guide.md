# Development & Contribution Notes

This page provides developers with the information required to develop support for additional products or make contributions to this project.

## How to contribute (Developers adding support for more SIEMs & platforms)

* Define the configuration for a given SIEM in:
  * An already created folder under [config](config). See [elastic](config/elastic) for reference.
  * Or create a new folder under [config](config) along with the configuration file and corresponding README. See [elastic](config/elastic) for reference.
* Setup Sigma repository.
* Setup SIEGMA repository.
* Under [rule_file_creator_scripts](rule_file_creator_scripts) folder, add a script by the name of the format that you want to support. For example: [es-qs.py](rule_file_creator_scripts/es-qs.py). This script shall contain all the heavy lifting for conversions. See [es-qs.py](rule_file_creator_scripts/es-qs.py) for reference. Only one function inside [es-qs.py](rule_file_creator_scripts/es-qs.py) gets called from [siegma.py](siegma.py) and performs all tasks.
* At the top of [siegma.py](../siegma.py), import your newly created script file.
* Go to create_rule_file_for_siem() in [siegma.py](../siegma.py). Add an if/else and point it to the function in your new_format.py.

## Folder Hierarchy
* **[config](config)**: Folder that contains sample and production configurations so rule file creation can take place.
  * **[elastic](config/elastic)**: Folder that contains Elastic SIEM configuration files.
* **[rule_file_creator_scripts](rule_file_creator_scripts)**: Folder that contains individual scripts that handle the heavy lifting for different formats.
* **[helpers](helpers)**: Folder containing helper scripts for siegma.py.