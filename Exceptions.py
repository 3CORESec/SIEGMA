# To get more information about the errors, user DEBUG verbosity level.

class RuleSyntaxError(Exception):
    """
        Error in the RuleSyntax.
    """

    pass

class CreateRuleViaApiError(Exception):
    """
        Error while creating the rule via API. e.g., Invalid SIEM resource
    """

    pass

class FileExtensionError(Exception):
    """
        File extension error, e.g., The SIEM requires a JSON and was provided a file with another extension.
    """

    pass
