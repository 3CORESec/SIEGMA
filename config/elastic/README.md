# Elastic SIEM config

This folder holds the configuration file for a specific platform. An explanation of the fields is available below. 

**Fields that are environment specific or for which there is no mapping in Sigma and require modification in the configuration file:**

* index
* interval
* from *(no need to change if you're using `timeframe` in Sigma)*

Please change these in the configuration before running SIEGMA.

## Elastic SIEM Configuration:

| Elastic SIEM Config | Value                 | Field type               | Description                                                           |
|---------------------|-----------------------|--------------------------|-----------------------------------------------------------------------|
| sigma_query_format  | es-qs                 | Hardcoded                | Preset value. This value is passed to sigmac                          |
| rule_id             | No default value      | Sigma: id                | Rule identifier                                                       |
| id                  | No default value      | Sigma: id                | Rule identifier                                                       |
| author              | No default value      | Sigma: author            | Rule author                                                           |
| from                | No default value      | Sigma: timeframe         | Defines how much data in the past should be queried. Example: now-15m |
| index               | No default value      | User input needed        | Define the indexes that should be queried. Example: filebeat-*        |
| interval            | No default value      | User input needed        | Define how often the rule should run in Elastic SIEM                  |
| language            | kuery                 | Hardcoded                | Preset field and value. Don't change                                  |
| output_index        | .siem-signals-default | Hardcoded                | Default index used by Elastic SIEM                                    |
| references          | No default value      | Sigma: references        | References and documentation related to the detection                 |
| falsepositives      | No default value      | Sigma: falsepositives    | Situation under which a false positive can trigger the detection      |
| risk_score          | No default value      | Sigma: severity          | low=25, medium=50, high=75, critical=100                              |
| name                | No default value      | Sigma: name              | Rule name                                                             |
| description         | No default value      | Sigma: description       | Rule description                                                      |
| query               | No default value      | Hardcoded                | Comes from the result of running sigmac                               |
| severity            | No default value      | Sigma: severity          | Rule severity                                                         |
| tags                | No default value      | Sigma: logsource.service | Tags to aid in rule identification                                    |
| to                  | now                   | Hardcoded                | Preset field and value. Don't change                                  |
| type                | query                 | Hardcoded                | Preset field and value. Don't change                                  |
| threat              | No default value      | Sigma: tags              | ATT&CK mapping                                                        |
| throttle            | no_actions            | Hardcoded                | Preset field and value. Don't change                                  |
