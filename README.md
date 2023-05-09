# SIEGMA

This project aims to automate the creation of SIEM rule consumables by leveraging a pre-defined set of configurations/mappings and by utilizing the [Sigma](https://github.com/Neo23x0/sigma) rule format engine and [pysigma](https://pypi.org/project/pysigma/) library in the converter processes.

<p align="center"><img align="center" src="https://i.imgur.com/zrtGgyb.png"></p>

It is also our objective to take a community approach to SIEM schemas, maintaining easy to read data dictionaries while making it trivial to add custom fields based on specific use cases.

For platforms that support it, SIEGMA also enables automatic upload of the SIEM consumable. Check the [Automatic Import](https://github.com/3CORESec/SIEGMA#siem-automatic-import) section for more information.

How does it differ from `pysigma`? The reason we decided to create our own artifacts is to have more control over the mappings and allow for a different level of automation. This project is not mean to be a replacement to Sigma or `pysigma`, especially since it utilizes `pysigma`.

## Supported SIEM's

- Elastic SIEM
- Azure Sentinel (in development)
- Splunk (in development)

# Installation

We'll run the software and install dependencies, for both this project as well as Sigma, under a Python virtual environment using poetry.

`pip3 install poetry`

- Setup Sigma
 
```
git clone https://github.com/SigmaHQ/sigma.git
```

- Setup SIEGMA

```
git clone https://github.com/3CORESec/SIEGMA
cd SIEGMA
poetry install
```

**Before running SIEGMA:** Sigma rules might not hold all required fields in use by your SIEM. To make sure that all fields are mapped correctly, each product holds a README where we warn you if there are fields that need to be filled before running this software.

Visit your SIEM [config](config/) folder to learn more about this.

# Usage

Invoke the script by providing it a Sigma rule or Sigma rule folder as well as the desired SIEM platform.

Activate the virtual environment:

`poetry shell`

It is recommended to consult the [docs](docs/) folder for help, especially for advanced usage instructions.

In order to provide examples for each specific platform, we have moved the examples section to their own README section inside of the [config folder](./config) of the SIEM in question.

Please consult each SIEM folder for detailed instructions on how to convert single Sigma files, folders, automatic upload and other options.

# Rules compliance

SIEGMA natively makes use of this script for rule format compliance check.

# SIEM Automatic Import

As part of our objective of developing tools, techniques and know-how to [Detection as Code](https://blog.3coresec.com/search/label/Detection), it has always been the goal of this project to allow the usage of SIEGMA in a CI/CD pipeline. By consulting the [automatic upload](docs/automatic-upload.md) document, you can gain a better understanding of the steps involved.

# Contributions and Development

Want to know more how it all comes together or want to contribute support for a new platform? Check the [development guide](./development-guide.md) for more information.

## Roadmap

- Additional platform/SIEM support
  - ~~Elastic SIEM~~
  - Azure Sentinel (To be developed)
  - Splunk (To be developed)
- Additional Features
  - Elastic
    - ~~Actions support~~

# Feedback

Found this interesting? Have a question/comment/request? Let us know!

Feel free to open an [issue](https://github.com/3CORESec/SIEGMA/issues) or ping us on [Twitter](https://twitter.com/3CORESec).

[![Twitter](https://img.shields.io/twitter/follow/3CORESec.svg?style=social&label=Follow)](https://twitter.com/3CORESec)
