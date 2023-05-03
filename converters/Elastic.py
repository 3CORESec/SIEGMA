from converters.ConvertorsBase import ConvertorsBase
from sigma.parser.collection import SigmaParser
from sigma.pipelines.elasticsearch.windows import ecs_windows
from Exceptions import CreateRuleByApiError, FileExtensionError
from tools.FileTools import FileTools
from sigma.rule import SigmaRule
from dataclasses import dataclass
from enum import Enum
import json
import requests
import secrets
import base64


class RiskSocreMapping(Enum):
    """
        Elastic risk socre mapping.
    """
 
    INFORMATIONAL = 1
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 100

    @classmethod
    def collect_risk_socre(cls, risk: str) -> int:
        """
            Use this function to collect the risk score.

        Args:
            risk (str): Risk level

        Returns:
            int: Return the number of risk associated with the rule.
        """     

        risk = risk.upper()

        if cls[risk] is not None:
            return cls[risk] 

        return cls.MEDIUM

@dataclass
class ElasticConverter(ConvertorsBase):
    """
        Elastic converter, use this class to convert sigma rule into elastic rule.
    
    Args:
        siem_config (dict[any, any]) : Siem configuration.
    """

    siem_config: dict[any, any]

    def write_rule(self, file_name: str, rule_infos: dict["str", any]) -> None:
        """
            Use this function to save the output into a file.

        Args:
            file_name (str): File name.
            rule_infos (any): Rule content. 
        """

        if FileTools.get_file_extension_name(file_name) != ".ndjson":
            raise FileExtensionError("Output file extension must be .ndjson")

        with open(file_name, 'a') as convert_file:
            convert_file.write(f"{str(json.dumps(rule_infos))}\n")

    def create_rule(self, sigma_rule: SigmaRule, query: str) -> dict[str, any]:
        """
            Use this function to create a elastic rule. 
        Args:
            sigma_rule (SigmaRule): Sigma rule content, use tools.SigmaUtils.SigmaRule.get_yml_file_content to create a SigmaRule object
            query (str): Query as string, use the convert method to get a query string

        Returns:
            any: Return the rule following each SIEM sintaxe.
        """

        elastic_config = self.siem_config
        mitre_attack_threat_mapping = self.create_elastic_attack_mapping([tag.name for tag in sigma_rule.tags])

        return {
            "rule_id": str(sigma_rule.id),
            "author": [author.strip() for author in sigma_rule.author.split(",")],
            "from": elastic_config["settings"]["from"],
            "index": elastic_config["settings"]["index"],
            "interval": elastic_config["settings"]["interval"],
            "language": elastic_config["settings"]["language"],
            "references": sigma_rule.references,
            "output_index": elastic_config["settings"]["output_index"],
            "false_positives": sigma_rule.falsepositives,
            "risk_score": RiskSocreMapping.collect_risk_socre(sigma_rule.level.name).value,
            "name": sigma_rule.title,
            "enabled": True,
            "description": sigma_rule.description,
            "query": query,
            "severity": sigma_rule.level.name.lower(),
            "tags": [tag.name for tag in sigma_rule.tags],
            "to": elastic_config["settings"]["to"],
            "type": elastic_config["settings"]["type"],
            "threat": mitre_attack_threat_mapping,
            "actions": elastic_config["settings"]["actions"],
            "note": elastic_config["settings"]["note"],
            "throttle": elastic_config["settings"]["throttle"]
        }

    def convert(self, sigma_parser_rule: SigmaParser, backend: callable) -> str:
        """
            Function responsible for converting a sigma rule into a elastic query.

        Args:
            sigma_rule (SigmaCollection): Sigma rule, use tools.SigmaUtils.SigmaRule.get_sigma_configuration to create a SigmaCollection. 
            backend (callable): Backend responsible for converting the rule.

        Returns:
            str: Return the query as string
        """ 

        rule = backend(ecs_windows()).convert(sigma_parser_rule)[0]

        return rule

    def create_rule_by_api(self, rule: dict[str, any], siem_url: str, username: str, _passwd: str, apikey="") -> dict[any, any]:
        """
            Create a new elastic rule by api.

        Args:
            rule (dict[str, any]): Rule content, use converter.elastic.create_rule to get a valid rule.
            username (str): Username to authenticate.
            __passwd (str): Password to authenticate.

        Raises:
            CreateRuleByApiError: Custom exception, if you see it, it means some error happened in the process. 

        Returns:
            dict[any, any]: Rule content.
        """

        credentials = bytes(f"{username}:{_passwd}", encoding="utf-8")
        encoded_credentials = base64.b64encode(credentials).decode("utf-8")
        xsrf_token = secrets.token_hex(16)

        resp = requests.post(f"{siem_url}/api/detection_engine/rules",
                            headers={
                                "Authorization": "Basic " + encoded_credentials,
                                "Content-Type": "application/json",
                                "kbn-xsrf": xsrf_token
                            },
                        json=rule)

        resp_content = resp.json()

        if resp.status_code != 200:
            raise CreateRuleByApiError(resp_content["message"])

        return resp.json()

    def create_elastic_attack_mapping(self, techniques: list[str]) -> dict[str, any]:
        """
            Gather information from a technique in the mitre attack mapping and return them as a elastic threat type.

        Args:
            techniques (list[str]): Techniques to search

        Returns:
            dict[str, any]: The informations of the given techniques.
        """

        mitre_attack_threat: dict[str, any] = []

        for tactic, infos in self.get_mitre_attack_mapping(techniques).items():
            mitre = {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": infos["tactic_id"],
                    "name": tactic,
                    "reference": infos["tactic_reference"]
                },
                "technique": []
                }

            for techinique in infos["techniques"]:
                mitre["technique"].append(
                    {
                        "id": techinique["id"],
                        "name": techinique["name"],
                        "reference": techinique["reference"]
                    }
                )

            mitre_attack_threat.append(mitre)

        return mitre_attack_threat