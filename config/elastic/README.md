# Elastic SIEM config

This folder holds the configuration file for a specific platform. An explanation of the fields is available below. 

**Fields that are environment specific or for which there is no mapping in Sigma and require modification in the configuration file:**

* from *(no need to change if you're using `timeframe` in your Sigma rules)*
* index
* interval
* kibana_username
* kibana_password
* kibana_url

Please change these in the configuration before running SIEGMA.

=======
## Elastic SIEM Configuration:

| Elastic SIEM Config | Default Value         | Field type               | Description                                                           | Value mandatory to be filled |
|---------------------|-----------------------|--------------------------|-----------------------------------------------------------------------|------------------------------|
| sigma_query_format  | es-qs                 | Hardcoded                | Preset value. This value is passed to sigmac                          | Yes                          |
| kibana_username     | No default value      | Hardcoded                | Hardcoded value that is used during rule file upload and install on Kibana. Empty value would mean that rule install and upload is not required| No                          |
| kibana_password     | No default value      | Hardcoded                | Hardcoded value that is used during rule file upload and install on Kibana. Empty value would mean that rule install and upload is not required| No                          |
| kibana_url          | No default value      | Hardcoded                | Hardcoded value that is used during rule file upload and install on Kibana. Empty value would mean that rule install and upload is not required| No                          |
| rule_id             | No default value      | Sigma: id                | Rule identifier                                                       | Yes                          |
| id                  | No default value      | Sigma: id                | Rule identifier                                                       | Yes                          |
| author              | No default value      | Sigma: author            | Rule author                                                           | No                           |
| from                | now-15m               | Sigma: timeframe         | Defines how much data in the past should be queried. Example: now-15m | Yes                          |
| index               | ["*"]                 | User input needed        | Define the indexes that should be queried. Example: filebeat-*        | Yes                          |
| interval            | 5m                    | User input needed        | Define how often the rule should run in Elastic SIEM                  | Yes                          |
| language            | kuery                 | Hardcoded                | Preset field and value. Don't change                                  | Yes                          |
| output_index        | .siem-signals-default | Hardcoded                | Default index used by Elastic SIEM                                    | No                           |
| references          | No default value      | Sigma: references        | References and documentation related to the detection                 | No                           |
| false_positives     | No default value      | Sigma: falsepositives    | Situation under which a false positive can trigger the detection      | No                           |
| risk_score          | No default value      | Sigma: severity          | low=25, medium=50, high=75, critical=100                              | Yes                          |
| name                | No default value      | Sigma: name              | Rule name                                                             | Yes                          |
| description         | No default value      | Sigma: description       | Rule description                                                      | Yes                          |
| query               | No default value      | Hardcoded                | Comes from the result of running sigmac                               | Yes                          |
| severity            | No default value      | Sigma: severity          | Rule severity                                                         | Yes                          |
| tags                | No default value      | Sigma: logsource.service | Tags to aid in rule identification                                    | No                           |
| to                  | now                   | Hardcoded                | Preset field and value. Don't change                                  | Yes                          |
| type                | query                 | Hardcoded                | Preset field and value. Don't change                                  | Yes                          |
| threat              | No default value      | Sigma: tags              | ATT&CK mapping                                                        | No                           |
| throttle            | no_actions            | Hardcoded                | Preset field and value. Don't change                                  | Yes                          |
