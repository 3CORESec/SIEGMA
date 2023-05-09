# To get more information about the errors, user DEBUG verbosity level.

class RuleSintaxeError(Exception):
    """
        Error in the RuleSintaxe.
    """

    pass

class CreateRuleByApiError(Exception):
    """
        Erro to create a rule by API. e.g. Invalid SIEM resource.
    """

    pass

class FileExtensionError(Exception):
    """
        File extension error, e.g. The SIEM needs a json and was passed a txt output file.
    """

    pass
