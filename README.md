# SIΣGMA

This project aims to automate the creation of SIEM rule consumables by leveraging a pre-defined set of configurations/mappings and by utilizing the [Sigma](https://github.com/Neo23x0/sigma) rule format and engine. 

<p align="center"><img align="center" src="https://i.imgur.com/laf6vv6.png"></p>

It is also our objective to take a community approach to SIEM schemas, maintaing easy to read data dictionaries while making it trivial to add custom fields based on specific use cases. 

For platforms that support it, SIΣGMA also enables automatic upload of the SIEM consumable. Check the [Automatic Import](https://github.com/3CORESec/SIEGMA#siem-automatic-import-feature) section for more information.

How does it differ from `sigmac`? It doesn't. The reason we decided to create our own artifacts is to have more control over the mappings and allow for a different level of automation. This project is not mean to be a replacement to Sigma or `sigmac`, especially since it utilizes `sigmac`. 

## Supported SIEM's

* Elastic SIEM
* Splunk Enterprise Security (future release)

# Installation

We'll run the software and install dependencies, for both this project as well as Sigma, under a Python virtual environment. 
      
`pip3 install pipenv` 
    
* Setup Sigma

```
git clone https://github.com/Neo23x0/sigma
cd sigma
pipenv install --skip-lock
```

* Setup SIEGMA

```
git clone https://github.com/3CORESec/SIEGMA
cd SIEGMA
pipenv install
```

*Note for Windows users*: Powershell must be enabled for command and script execution. Open `Administrative Powershell` and execute following command: `Set-ExecutionPolicy Bypass` 

**Before running SIEGMA:** Sigma rules might not hold all required fields in use by your SIEM. To make sure that all fields are mapped correctly, each product holds a README where we warn you if there are fields that need to be filled before running this software.

Visit your SIEM [config](config/) folder to learn more about this.

# Usage
 
Invoke the script by providing it a Sigma rule or Sigma rule folder as well as the desired SIEM platform. 

Activate the virtual environment:
 
`pipenv shell`
   
It is recommended to consult the `siegma.py` help, especially for advanced usage instructions:
 
`python siegma.py -h`

## Generate an Elastic SIEM output from a single Sigma rule file
 
`python siegma.py -c config/elastic/elastic-siem.json -r /path/to/rule.yml -s /path/to/sigma/folder -sc /path/to/sigma/config/file/sigma/tools/config/file.yml -o rule-output`
 
## Generate an Elastic SIEM output from a folder with several Sigma rule files

`python siegma.py -c config/elastic/elastic-siem.json -r /path/to/folder/with/sigma-rules/ -s /path/to/sigma/folder -sc /path/to/sigma/config/file/sigma/tools/config/file.yml -o rule-output`

An example where we utilize our [AWS CloudTrail Sigma configuration](https://blog.3coresec.com/2020/05/contributions-to-sigma-cloudtrailecs.html) to convert a single rule to Elastic SIEM output:

`python siegma.py -c config/elastic/elastic-siem.json -r rules/cloudtrail_rule.yml -s sigma/ -sc sigma/tools/config/ecs-cloudtrail.yml -o rule-output`

## Generate an Elastic SIEM output from a rule file and also pass Sigma backend options

In this example we will utilize `-sep` to request SIEGMA to use the advanced Sigma backend options that would be defined in the [Elastic config](config/elastic/)

`python siegma.py -c config/elastic/elastic-siem.json -r /path/to/folder/with/sigma-rules/rule.yml -s /path/to/sigma/folder -sc /path/to/sigma/config/file/sigma/tools/config/file.yml -sep -o output-file`

## Generate an Elastic SIEM output from a rule file and also override elastic-siem.json config from commandline

In this example we will utilize the [Elastic config](config/elastic/) fields as they are definied *(or supplied from the Sigma rule)* **while** overwriting certain fields through the usage of `-co`. This is particularly useful if converting Sigma rules for which you'd like to apply different SIEM consumable fields. 

The example below will overwrite the `settings.author`, `credentials.kibana_url` and `credentials.kibana_username`.  

`python siegma.py -c config/elastic/elastic-siem.json -r /path/to/folder/with/sigma-rules/rule.yml -s /path/to/sigma/folder -sc /path/to/sigma/config/file/sigma/tools/config/file.yml -co settings.author=none,credentials.kibana_url="www.example.com",credentials.kibana_username="bfd" -o output-file`

# Rules compliance

SIEGMA natively makes use of this script for rule format compliance check.

However, to manually check if the rules are in the correct format and processable by SIEGMA, run following commands:

```
cd helpers
python check_if_compliant.py -p path/to/rules/directory/
```

# SIEM Automatic Import

If you'd like to enable automatic upload of consumables into your SIEM, please enter your environment variables in the [config](config/) of your platform or specify them through `-co` as previously shown. 

# Contributions and Development

Want to know more how it all comes together or want to contribute support for a new platform? Check the [development guide](./development-guide.md) for more information. 

## Roadmap

- Additional platform/SIEM support
  - Sentinel (To be developed)
  - Splunk (To be developed)
- ~~Enable use of sigma backend options~~
- ~~Override siegma config from the commandline~~
- ~~Functionality to create aggregate rules in Elastic/Kibana using `es-qs` as backend~~
- ~~Enable notes/investigation guide addition to Kibana using es-qs as backend~~
- ~~Compliance check for rules if they are in the format that is supported by siegma or not~~
- ~~Add rule format compliance check~~
- ~~Remove sigma virtualenv and shift to pipenv~~
- ~~Get rid of sigma virtual environment switch and parameter~~

# Feedback

Found this interesting? Have a question/comment/request? Let us know! 

Feel free to open an [issue](https://github.com/3CORESec/SIEGMA/issues) or ping us on [Twitter](https://twitter.com/3CORESec). We also have a [Community Slack](https://launchpass.com/3coresec) where you can discuss our open-source projects, participate in giveaways and have access to projects before they are released to the public.

[![Twitter](https://img.shields.io/twitter/follow/3CORESec.svg?style=social&label=Follow)](https://twitter.com/3CORESec)
