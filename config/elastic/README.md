# Elastic SIEM config

This folder holds the configuration file for a specific platform. An explanation of the fields is available below. 

**Fields that are environment specific or for which there is no mapping in Sigma and require modification in the configuration file:**

* index
* from *(no need to change if you're using `timestamp` in Sigma)*
* interval

Please change these in the configuration before running SIEGMA.

## Elastic SIEM Fields:
```
{
    "sigma_query_format": "es-qs", -> # Required field & value pair for Kibana ndjson type file query creation. This value is passed to sigmac as -t switch to create the appropriate query that can be embedded in the Elastic SIEM ndjson.
    "settings": -> # A key that contains within the required fields for Kibana ndjson rule file creation from a given Sigma file. {
        "rule_id": "", -> # Mandatory field that is automatically set from the Sigma rule file id field. ruld_id and id have same value.
        "id": "", -> # Mandatory field that is automatically set from the Sigma rule file id field. ruld_id and id have same value.
        "author":[], -> # Field to mention authors. You can predefine authors here or value can be automatically set from the author field in Sigma rule file. 
        "from":"", -> # Required. Value can be set here in config file or can be updated using the detection.timeframe section of the yml rule file. Defines how much data in the past should be queried when Kibana will execute this query. Example values can include like now-1200s or the usual ELK time query values.
        "index":[], -> Required. Value needs to be set here in config. Defines the index patterns on which this query would execute. Eg: functionbeat-*.
        "interval":"", -> # Required. Value needs to be set here in config. Defines how often should the query execute. For example: 5m.
        "language":"kuery", -> # Required. Preset field and value. Do not change.
        "output_index":"", -> # Required. Value needs to be set in config. Defines the index where the results for query execution and search should be saved. Eg: search_results.
        "references":[], -> # Value is taken from the references field in Sigma rule.
        "falsepositives":[], -> # Value is taken from the falsepositives field in Sigma rule.
        "risk_score":0, -> # Value is automatically set and taken from the severity level field from Sigma rule. low=25. medium=50. high=75. critical=100.
        "name":"", -> # Value is taken from the name field in Sigma rule.
        "description":"", -> # Value is taken from the description field in Sigma rule.
        "query":"", -> # Value is taken from the result of the Sigma rule conversion on the provided sigma_query_format using sigmac.
        "severity":"", -> # Value is taken from the severity level field from Sigma rule.
        "tags":[], -> # Value is taken from the logsource.service field from Sigma rule.
        "to":"now", -> # Value is predefined and should not be changed.
        "type":"query", -> # Value is predefined and should not be changed.
        "threat":[], -> # Value is taken from the tags field in Sigma rule.
        "throttle":"no_actions" -> # Value is predefined and should not be changed.
    }
}
```
