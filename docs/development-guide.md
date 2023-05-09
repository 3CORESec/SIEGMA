# Development & Contribution Notes

This page serves as a valuable resource for developers who are interested in contributing to the project or extending support for additional products. It provides the necessary information and guidance to facilitate the development process and make meaningful contributions to the project's growth.

## How to contribute (Developers adding support for more SIEMs & platforms)

- Define the configuration for a given SIEM in:
  * An already created folder under [config](../config/). See [elastic](../config/elastic) for reference.
  * Or create a new folder under [config](../config) along with the configuration file and corresponding README. See [elastic](../config/elastic) for reference.
* Setup SIEGMA repository.
* Under the [backend](../backends/) folder, add a script by the name of the format that you want to support. For example: [Elastic.py](../backend/elastic.py). This script shall contain all the heavy lifting for conversions.
* To create a new backend converter, you need to create a new class that ends with `Backend`. Eg `class MyAwesomeBackend`, you need to do this for the [all_backends](../backends/__init__.py) mapping collect the new backend.
* Inside the new class, you need to implement the following functions:
  - create_rule_by_api: This function is responsible for creating a new backend rule using the API.
  - create_rule: This function is used to create a rule following the SIEM syntax.
  - write_rule: This function allows you to save the output into a file.
  - convert: This function is responsible for converting a sigma rule.

Please consult the [backend documentation](backend.md) for more information about these functions, including their specific usage, parameters, and return values.

* In the [Backend.py](../backends/BackendBase.py) script, import the backend module from [pysigma](https://pypi.org/project/pysigma/) and include it in the Backend enum class. 
