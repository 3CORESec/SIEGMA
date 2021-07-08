# Azure Sentinel

This folder holds the configuration file for the SIEM platform in question. All SIEM platform folders have the following structure:

- Example use cases of SIEGMA
- Fields & Configurations
- Automatic upload

## Example use cases of SIEGMA

### Generate a Sentinel SIEM output from a single Sigma rule file

TODO

## Fields that are worth looking into to adapt to your particular use case

| Azure Sentinel SIEM Config Field | Description                                                                                                                             | Example                                                                               |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| sigma_params                     | Used in conjunction with switch --sigma_extra_parameters. Dictionary under which any of the parameters supported by Sigma can be added. | {"sigma_params": {"--backend-option": ["key=value", "case_insensitive_whitelist=*"]}} |

## Azure Sentinel SIEM Configuration & Data Dictionary

| Azure Sentinel SIEM Config Field | Default Value                         | Field type                 | Description                                                                                                                                                                                                                             |
| -------------------------------- | ------------------------------------- | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| sigma_query_format               | ala-rule                              | Hardcoded                  | Preset value. This value is passed to sigmac                                                                                                                                                                                            |
| sigma_params                     | N/A                                   | User input optional        | Used in conjunction with switch --sigma_extra_parameters. Dictionary under which any of the parameters supported by Sigma can be added. Example: {"sigma_params": {"--backend-option": ["key=value", "case_insensitive_whitelist=*"]}}  |
| azure_client_id                  | No default value                      | User input optional        | Enables automatic rule upload if filled                                                                                                                                                                                                 |
| azure_client_secret              | No default value                      | User input optional        | Enables automatic rule upload if filled                                                                                                                                                                                                 |
| azure_tenant_id                  | No default value                      | User input optional        | Enables automatic rule import if filled                                                                                                                                                                                                 |
| azure_subscription_id            | No default value                      | User input optional        | Enables automatic rule import if filled                                                                                                                                                                                                 |
| azure_resource_group             | No default value. Resource group name | User input optional        | Enables automatic rule import if filled                                                                                                                                                                                                 |
| queryPeriod                      | PT15M                                 | User input optional        | Defines how much data in the past should be queried. Example: PT15M                                                                                                                                                                     |
| queryFrequency                   | PT5M                                  | User input optional        | Configuration that specifies after what interval should the query execute. Example: PT5M                                                                                                                                                |
| kind                             | Scheduled                             | User input needed          | Define the rule type. Example: Scheduled                                                                                                                                                                                                |
| triggerOperator                  | GreaterThan                           | User input optional        | Define the comparison operator between query results and results count. Eg: GreaterThan                                                                                                                                                 |
| triggerThreshold                 | 0                                     | User input optional        | Define the threshold for the query results count                                                                                                                                                                                        |
| suppressionDuration              | PT1H                                  | User input optional        | Define the time period after the first rule trigger during which the rule shall be suppressed and not triggered again                                                                                                                   |
| suppressionEnabled               | false                                 | User input optional        | Define if the rule suppression for a certain time after first trigger should be enabled or not. Eg: false                                                                                                                               |
| notes_folder                     | No default value                      | Sigma Config: notes_folder | Contains path to a folder that contains .md (markdown formatted) file containing details for investigation guide / notes for a given detection use case. Optional field that can be set either in config or using -co from commandline. |

## Automatic upload

TODO

If you'd like to enable automatic upload of consumables into your SIEM, please enter your environment variables in the [config files](/) or specify them through `-co` as previously shown.
