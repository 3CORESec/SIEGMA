from sigma.validators.core.condition import AllOfThemConditionValidator
from dataclasses import dataclass
from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator 
from sigma.configuration import SigmaConfiguration
from Exceptions import RuleSintaxeError


def get_sigma_configuration(sigma_config_file_path : str) -> SigmaConfiguration:
    """
        Use this function to load the sigma configuration.

    Args:
        sigma_config_file_path (str): Pass the path to the configuration file.

    Returns:
        SigmaConfiguration: Returns the sigma configuration object.
    """

    with open(sigma_config_file_path, 'r') as config_file:
        sigma_configs = SigmaConfiguration(configyaml=config_file)

    return sigma_configs

@dataclass(kw_only=True)
class SigmaRule:
    """
        Class responsible for performing actions on Sigma rules. 

        Args:
            file_path (str): Path of the sigma rule.
            sigma_config (SigmaConfiguration): SigmaConfiguration object, use tools.SigmaUtils.get_sigma_configuration to generate it.

    """
  
    file_path: str
    sigma_config: SigmaConfiguration

    def get_yml_file_content(self) -> SigmaCollection:
        """
            Get the contents of a yml file and return it as SigmaCollection.

        Returns:
            SigmaCollection: The contents of a yml file.
        """

        with open(self.file_path, "r") as file:
            rule = SigmaCollection.from_yaml(file)

        return rule

    def check_rule_sintaxe(self, rule: SigmaCollection) -> None:        
        """
            Check if the rule sintaxe is satisfied.

        Args:
            rule (SigmaCollection): Loaded sigma rule object.

        Raises:
            RuleSintaxeError: Rule sintaxe error exception.
        """

        rule_validator = SigmaValidator(validators={AllOfThemConditionValidator})

        issues = rule_validator.validate_rules(rule)

        if len(issues) > 0:
            raise RuleSintaxeError(f"Issues in the rule sintaxe. Errors: {issues}")

