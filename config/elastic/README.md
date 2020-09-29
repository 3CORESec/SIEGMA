# Elastic SIEM config

This folder holds the configuration file for a specific platform. An explanation of the fields is available below. 

**Fields that are worth looking into to adapt to your particular use case:**

| Elastic SIEM Config Field | Description                                                       | Example                                              | 
|---------------------------|-------------------------------------------------------------------|-------------------------------------------------------
| from                      | No need to change if you're using `timeframe` in your Sigma rules | now-15m                                              |
| timeline_id               | Not included in the configuration but can be added               | "timeline_id":"e17d2870-6bb5-11ea-9871-d10df4e7cd14" |
| timeline_title            | Not included in the configuration but can be added               | "timeline_title":"AWS Cloud Trail"                   |


## Elastic SIEM Configuration & Data Dictionary 

| Elastic SIEM Config Field  | Default Value         | Field type               | Description                                                           | 
|----------------------------|-----------------------|--------------------------|-----------------------------------------------------------------------|
| sigma_query_format         | es-qs                 | Hardcoded                | Preset value. This value is passed to sigmac                          |
| kibana_username            | No default value      | User input optional      | Enables automatic rule upload if filled                               |
| kibana_password            | No default value      | User input optional      | Enables automatic rule upload if filled                               |
| kibana_url                 | No default value      | User input optional      | Enables automatic rule upload if filled (i.e http://kibana_url:port)  | 
| rule_id                    | No default value      | Sigma: id                | Rule identifier                                                       |
| id                         | No default value      | Sigma: id                | Rule identifier                                                       |
| author                     | No default value      | Sigma: author            | Rule author                                                           |
| from                       | now-15m               | Sigma: timeframe         | Defines how much data in the past should be queried. Example: now-15m |
| index                      | ["*"]                 | User input needed        | Define the indexes that should be queried. Example: filebeat-*        |
| interval                   | 5m                    | User input needed        | Define how often the rule should run in Elastic SIEM                  |
| language                   | kuery                 | Hardcoded                | Preset field and value. Don't change                                  |
| output_index               | .siem-signals-default | Hardcoded                | Default index used by Elastic SIEM                                    |
| references                 | No default value      | Sigma: references        | References and documentation related to the detection                 |
| false_positives            | No default value      | Sigma: falsepositives    | Situation under which a false positive can trigger the detection      |
| risk_score                 | No default value      | Sigma: severity          | low=25, medium=50, high=75, critical=100                              |
| name                       | No default value      | Sigma: name              | Rule name                                                             |
| description                | No default value      | Sigma: description       | Rule description                                                      |
| query                      | No default value      | Hardcoded                | Comes from the result of running sigmac                               |
| severity                   | No default value      | Sigma: severity          | Rule severity                                                         |
| tags                       | No default value      | Sigma: logsource.service | Tags to aid in rule identification                                    |
| to                         | now                   | Hardcoded                | Preset field and value. Don't change                                  |
| type                       | query                 | Hardcoded                | Preset field and value. Don't change                                  |
| threat                     | No default value      | Sigma: tags              | ATT&CK mapping                                                        |
| throttle                   | no_actions            | Hardcoded                | Preset field and value. Don't change                                  |
| timeline_id                | No default value      | Must be added to config  | SIEM Timeline ID (i.e e17d2870-6bb5-11ea-9871-d10df4e7cd14)           |
| timeline_title             | No default value      | Must be added to config  | Desired name to be associated with the Timeline (i.e AWS CloudTrail)  |
