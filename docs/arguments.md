# Arguments 

A brief documentation detailing all the available arguments.

---

- -h, --help

Show all the available arguments and their descriptions.


- -config, --config
Config file path. Eg: /path/to/config.json.

This argument is **MANDATORY**.

```
dest: config
```

- -b, --backend

SIEM backend used for the conversion process. Eg: elastic

This argument is **MANDATORY**.

```
dest: backend
```
- --api

To create a rule in the SIEM using the API, include this argument when executing the command.

```
dest: api
```
- -p , --path

Provide the file or folder path for the rule. The path should be either an absolute path from the root folder or a relative path to the sigma folder, not the siegma folder. Eg: /path/to/rule/file.yml or /path/to/rules/folder.

This argument is **MANDATORY**.

```
dest: path
default: False
```

-sc --sigma_config

Sigma config file path. Eg: /path/to/sigma/tools/config/ecs-cloudtrail.yml.

```
dest: sigma_config_file
```

- -o --output
SIEM rule output file name. Eg: output.json.

```
dest: output_file
default: .output.ndjson
```

- -v --verbosity

Execution verbosity level. Eg: INFO|WARN|DEBUG|ERROR

```
dest: verbosity_level
default: INFO
```

- -lf , --log_file 

- File to save the logs infos.
```
dest: verbosity_level
default: .output.log
```