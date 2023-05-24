# Backend

Backends are responsible for converting Sigma rules into target query languages and automatically uploading them to the desired SIEM platform. In this project, the conversion process is handled by the [pySigma library](https://pypi.org/project/pysigma/).

---

## Backends

To create a new Backend, you can utilize the [pySigma](https://pypi.org/project/pysigma/) library, which provides mapping for SIEM platforms, conversion processes, pipelines, and other helpful functions. For detailed instructions and examples, it is recommended to refer to the pySigma repository.

You can visit the [pySigma repository](https://github.com/SigmaHQ/pySigma) on platforms such as GitHub or the [official package docs](https://sigmahq-pysigma.readthedocs.io/en/latest/index.html). These sources provide comprehensive documentation, code samples, and examples specific to the Backends module. Accessing the repository will allow you to gain a deeper understanding of how to import, utilize, and create new Backends using the pysigma library.

---

## Implementation example

To create a new backend instance, use the base backend located at the `backend.BackendBase` abstract class.

```python
from BackendBase import BackendBase

class MyAwesomeBackend(BackendBase)
    # implementation details here
```

MyAwesomeBackend will need to implement some functions to work, such as:

```python
convert(sigma_rule: SigmaCollection, backend: callable) -> str:
    """
    Function responsible for converting a sigma rule.

    Arguments:
        sigma_rule (SigmaCollection): Sigma rule, use `tools.SigmaUtils.SigmaRule.get_sigma_configuration` to create a SigmaCollection. 
        backend (callable): Backend responsible for converting the rule.

    Returns:
        str: Return the query as string
    """
```

```python
write_rule(file_name: str, rule_infos: any) -> None:
    """
    Use this function to save the output into a file.

    Args:
        file_name (str): File name.
        rule_infos (any): Rule content. 
    """
```

```python
create_rule(sigma_rule: SigmaRule, query: str) -> any:
    """
    Use this function to create a rule following the SIEM syntax. 

    Args:
        sigma_rule (SigmaRule): Sigma rule content, use `tools.SigmaUtils.SigmaRule.get_yml_file_content` to create a SigmaRule object
        query (str): Query as string, use the `convert` method to get a query string

    Returns:
        any: Return the rule following each SIEM syntax.
    """
```

```python
create_rule_by_api(rule: dict[str, any], siem_url: str="", username: str="", __passwd: str="", apikey: str="") -> any:
    """
    Create a new elastic rule via API.

    Args:
        rule (dict[str, any]): Rule content, use `converter.elastic.create_rule` to get a valid rule.
```

All of these functions are required when creating a new backend, To see a practical example, take a look at the Elastic backend.

For a comprehensive understanding of how a rule is converted, please refer to the documentation of the pySigma library, which can be found [here](https://sigmahq-pysigma.readthedocs.io/en/latest/index.html)


---

## Collect all backends

To retrieve all available backends, you can use the backends.Backends.Backends located in the [Backends](..\backends\Backends.py) file. This contains a collection of all the available backends in the project.

Example:

```python
from backends.Backends import Backends

print(Backends._member_names_)
```
