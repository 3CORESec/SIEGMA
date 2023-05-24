from abc import ABC, abstractclassmethod
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from tools.MitreAttack import get_techinique_infos
import re

class BackendBase(ABC):
    """
        Convertors abstract base class. use this class to create a new converter.
    """
    def __init__(self, siem_config: dict[any, any]):
        """
            Class Inicializer

        Args:
            siem_config (dict[any, any]): Pass the siem configuration.
        """

    @abstractclassmethod
    def convert(self, sigma_rule: SigmaCollection, backend: callable) -> str:
        """
            Function responsible for converting a sigma rule.

        Args:
            sigma_rule (SigmaCollection): Sigma rule, use tools.SigmaUtils.SigmaRule.get_sigma_configuration to create a SigmaCollection. 
            backend (callable): Backend responsible for converting the rule.

        Returns:
            str: Return the query as string
        """        

    @abstractclassmethod
    def write_rule(self, file_name: str, rule_infos: any) -> None:
        """
            Use this function to save the output into a file.

        Args:
            file_name (str): File name.
            rule_infos (any): Rule content. 
        """        

    @abstractclassmethod
    def create_rule(self, sigma_rule: SigmaRule, query: str) -> any:
        """
            Use this function to create a rule following the SIEM syntax. 
        Args:
            sigma_rule (SigmaRule): Sigma rule content, use tools.SigmaUtils.SigmaRule.get_yml_file_content to create a SigmaRule object
            query (str): Query as string, use the convert method to get a query string

        Returns:
            any: Return the rule following each SIEM syntax.
        """

    def create_rule_by_api(self, rule: dict[str, any], siem_url: str="", username: str="", __passwd: str="", apikey: str="") -> any:
        """
            Create a new elastic rule by api.

        Args:
            rule (dict[str, any]): Rule content, use converter.elastic.create_rule to get a valid rule.
            siem_url (str): SIEM URL.
            username (str): Username to authenticate.
            __passwd (str): Password to authenticate.
            apikey (str): ApiKey to authenticate.

        Returns:
            any: SIEM response.
        """

    def get_mitre_attack_mapping(self, rule_tags: list[str]) -> dict[str, dict[str | list[dict[str, str]]]]:
        """
            Gather information from a technique in the mitre attack 

        Args:
            rule_tags (list[str]): Techinique IDs

        Returns:
            dict[str, dict[str | list[dict[str, str]]]]: The information of the technique.
        """        
        
        mitre_attack_mapping = {}
        
        for tag in rule_tags:
            if not re.match(r"^t\d", tag):
                continue

            techinique_infos = get_techinique_infos(tag.upper())

            if techinique_infos == None:
                continue

            for tactic_infos in techinique_infos["tactics"]:
                if not mitre_attack_mapping.get(tactic_infos["name"]):
                    mitre_attack_mapping[tactic_infos["name"]] = {"tactic_id": tactic_infos["id"], "tactic_reference": tactic_infos["reference"], "techniques": []}
               
                mitre_attack_mapping[tactic_infos["name"]]["techniques"].append(techinique_infos)

        return mitre_attack_mapping
