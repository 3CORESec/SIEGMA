import os
import re
import copy
import json
import requests
import subprocess
from pprint import pprint
from helpers.utils import get_slash_set_path, get_slashes


def get_author_name(query_d, yj_rule_d, logger):
    ret = None
    ret = query_d.replace(' by {}'.format(str(yj_rule_d)), '')
    return ret


def dump_to_file(dictionary, output='.output.azure.txt'):
    try:
        with open(output, "w") as outfile:
            json.dump(dictionary, outfile)
            outfile.write('\n')
            print('dict dumped to file {}'.format(output))
    except Exception as e:
        print("Exception {} occurred in dump_to_file()...".format(e))
    return output


def get_risk_score(severity):
    ret = 15
    if severity == 'low': ret = 25
    elif severity == 'medium': ret = 50
    elif severity == 'high': ret = 75
    elif severity == 'critical': ret = 100
    else: ret = 0
    return ret


def get_tags(tag_metadata):
    ret = []
    ret_aws = ['aws', 'cloudtrail']
    if tag_metadata in ret_aws:
        ret = ret_aws
    return ret


def is_technique(attack, item):
    print('Starting is_technique()...')
    is_technique_boolean = False
    technique = {}
    match_list = re.findall(r'^attack\.t\d{4,}$', item)
    print(match_list)
    if len(match_list) > 0:
        print(match_list)
        is_technique_boolean = True
        technique = get_technique_from_mitre(attack, item.replace('attack.', ''))
        # if technique: is_technique_boolean = True
    print('technique item {} data:'.format(item))
    pprint(technique)
    return is_technique_boolean, technique


def get_technique_from_mitre(attack, technique_id):
    found = False
    print('Starting get_technique_from_mitre()...')
    ret = {
        'id': technique_id,
        'name': technique_id,
        'reference': ''
    }
    for technique in attack.enterprise.techniques:
        if technique.id.lower() == technique_id:
            print(technique.id)
            print(technique.name)
            print(technique.wiki)
            ret['id'] = technique.id
            ret['name'] = technique.name
            ret['reference'] = technique.wiki
            found = True
            break
    # in case of an incorrect technique ID, it won't be detected so we need to let the parent function know that we failed to find the unknown technique.
    # if not found: ret = None
    return ret


def get_tactic_from_mitre(attack, item):
    print(f'Starting get_tactic_from_mitre() for item {item}...')
    ret = {
        'id': '',
        'name': '',
        'reference': ''
    }
    for tactic in attack.enterprise.tactics:
        # print('Tactic name: ')
        # print(tactic.name)
        if tactic.name.lower() == item:
            # print(tactic.id)
            # print(tactic.name)
            # print(tactic.wiki)
            ret['id'] = tactic.id
            ret['name'] = tactic.name
            ret['reference'] = tactic.wiki
    return ret


def is_tactic(attack, item):
    print('Starting is_tactic()...')
    is_tactic_boolean = False
    tactic = {}
    match_list = re.findall(r'^attack\.\w{5,}.*$', item)
    if item.count('.') > 1: match_list = []
    # print(match_list)
    if len(match_list) > 0:
        # print(match_list)
        is_tactic_boolean = True
        tactic = get_tactic_from_mitre(attack, item.replace('attack.', '').replace('_', ' '))
    print('tactic item {} data:'.format(item))
    pprint(tactic)
    return is_tactic_boolean, tactic


def get_subtechnique_from_mitre(attack, item):
    print(f'Starting get_subtechnique_from_mitre() for item {item}...')
    ret = {
        'id': '',
        'name': '',
        'reference': ''
    }
    for technique in attack.enterprise.techniques:
        for subtechnique in technique.subtechniques:
            if subtechnique.id.lower() == item:
                print(subtechnique.id)
                print(subtechnique.name)
                print(subtechnique.wiki)
                ret['id'] = subtechnique.id
                ret['name'] = subtechnique.name
                ret['reference'] = subtechnique.wiki
    return ret


def is_subtechnique(attack, item):
    print('Starting is_subtechnique()...')
    is_subtechnique_boolean = False
    subtechnique = {}
    match_list = re.findall(r'^(attack\.t\d{4,})\.\d+$', item)
    # print(match_list)
    if len(match_list) > 0:
        # print(match_list)
        is_subtechnique_boolean = True
        subtechnique = get_subtechnique_from_mitre(attack, item.replace('attack.', ''))
    return is_subtechnique_boolean, subtechnique


def get_mitre_ttps(attack, yj_rule, logger):
    # Sample MITRE TTPs format
    # tags:
    # - attack.defense_evasion
    # - attack.t1562
    # - attack.t1078.004
    # - attack.defense_evasion
    # - attack.t1562
    # - attack.t1078.004
    ret = []
    temp = {
        'framework': 'MITRE ATT&CK',
        'tactic': {},
        'technique': []
    }
    # individual_technique_object = {
    #     'id': '',
    #     'reference': '',
    #     'name': ''
    # }
    idx = 0
    # Read tactic.
    for item in yj_rule[idx:]:
        temp2 = copy.deepcopy(temp)
        logger.debug(f'item: {item}\tidx: {idx}')
        is_tactic_boolean, tactic = is_tactic(attack, item)
        logger.debug(f'is_tactic_boolean: {is_tactic_boolean}')
        temp2['tactic'] = tactic
        if is_tactic_boolean:
            logger.debug('Now inside tactic techniques if/else...')
            idx += 1
            logger.debug('Current idx after ++: {}'.format(idx))
            logger.debug('len_uj_rule ++: {}'.format(len(yj_rule)))
            if idx <= len(yj_rule) - 1:
                # Read techniques below
                logger.debug('Started inside for loop...')
                for idx2, item2 in enumerate(yj_rule[idx:]):
                    logger.debug('for loop is_technique part...')
                    is_technique_boolean, technique = is_technique(attack, item2)
                    if not is_technique_boolean:
                        # Read subtechniques
                        logger.debug('for loop not is_technique part...')
                        is_subtechnique_boolean, subtechnique = is_subtechnique(attack, item2)
                        if not is_subtechnique_boolean:
                            logger.debug('for loop not is_subtechnique part...')
                            break
                        if is_subtechnique_boolean:
                            logger.debug('for loop is_subtechnique part...')
                            temp2['technique'].append(subtechnique)    
                    if is_technique_boolean:
                        temp2['technique'].append(technique)
                    idx += idx2
                logger.debug('Finished inside for loop...')
        # So only non-empty and valid tactics and techniques make it to the final output
        if temp2.get('tactic') != {} and temp2.get('technique') != [] and temp2.get('tactic').get('id') != '':
            ret.append(temp2)
    # pprint(temp)
    pprint(ret)
    return ret


def valid_credentials(credentials, logger):
    ret = False
    creds_exist = client_id_exist = tenant_id_exist = client_secret_exist = subscription_id_exist = resource_group_exist = False
    if credentials and credentials is not None:
        creds_exist = True
        logger.debug('Credentials key exists...')
        logger.debug('Checking further...')
        if 'azure_client_id' in credentials:
            if credentials.get('azure_client_id') and credentials.get('azure_client_id') != '':
                client_id_exist = True
                logger.debug('client_id exists...')
        if 'azure_client_secret' in credentials:
            if credentials.get('azure_client_secret') and credentials.get('azure_client_secret') != '':
                client_secret_exist = True
                logger.debug('client_secret exists...')
        if 'azure_tenant_id' in credentials:
            if credentials.get('azure_tenant_id') and credentials.get('azure_tenant_id') != '':
                tenant_id_exist = True
                logger.debug('tenant_id exists...')
        if 'azure_subscription_id' in credentials:
            if credentials.get('azure_subscription_id') and credentials.get('azure_subscription_id') != '':
                subscription_id_exist = True
                logger.debug('subscription_id exists...')
        if 'azure_resource_group' in credentials:
            if credentials.get('azure_resource_group') and credentials.get('azure_resource_group') != '':
                resource_group_exist = True
                logger.debug('resource_group exists...')
    if creds_exist and client_id_exist and tenant_id_exist and client_secret_exist and subscription_id_exist and resource_group_exist:
        ret = True
        logger.info('Existing creds found. Output file shall be uploaded to Azure...')
    else:
        ret = False
        logger.info('No creds found. Output file shall not be uploaded to Azure...')
    return ret


def handle_response_errors(status_code, message, logger):
    if status_code == 400 and 'invalid file extension'.lower() in message.lower():
        logger.error('Use .azure.txt as the file extension for output file...')


def get_access_token(credentials, logger):
    token = None
    url = "https://login.microsoftonline.com/{}/oauth2/token".format(credentials.get('azure_tenant_id'))

    payload='grant_type=client_credentials&client_id={}&client_secret={}&resource=https%3A%2F%2Fmanagement.azure.com%2F'.format(credentials.get('azure_client_id'), credentials.get('azure_client_secret'))
    # headers = {
    #     'Content-Type': 'application/x-www-form-urlencoded',
    #     'Cookie': 'fpc=AqQZYV-ZmzxNuM0xabApxT4ac0cgAQAAAGqGVNgOAAAA'
    # }

    # response = requests.request("POST", url, headers=headers, data=payload)

    response = requests.request("POST", url, data=payload)

    logger.debug('creds response:')
    logger.debug(response.text)
    pprint(response.json())
    logger.debug('status code: {}'.format(response.status_code))

    token = response.json().get('access_token')

    return token


def install_rules(script_dir, credentials, rule_file, yj_rule, logger):
    return_status = 0
    token = None
    token = get_access_token(credentials, logger)
    if token is None:
        return_status = 1
    else:
        # rule_file_json = json.load(open(rule_file))

        url = "https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{1}/providers/Microsoft.SecurityInsights/alertRules/{2}?api-version=2020-01-01".format(credentials.get('azure_subscription_id'), credentials.get('azure_resource_group'), yj_rule.get('id'))

        payload = json.dumps(json.load(open(rule_file)))
        headers = {
            'Authorization': 'Bearer {}'.format(token),
            'Content-Type': 'application/json'
        }

        response = requests.request("PUT", url, headers=headers, data=payload)

        logger.debug('rule import response:')
        logger.debug(response.text)
        pprint(response.json())
        logger.debug('status code: {}'.format(response.status_code))

        if response.status_code >= 200 and response.status_code <= 299:
            return_status = 0
            logger.info('Rule {} successfully installed on Azure Sentinel...'.format(yj_rule.get('id')))
        else:
            return_status = 1
            logger.error('Rule {} could not be installed on Azure Sentinel...'.format(yj_rule.get('id')))

    return return_status


def rate_based_rule_settings(sigma_config, config, config_t, yj_rule_t, logger):
    # directly make changes to config variable and then return it at the end
    temp = {}
    update_required = False
    try:
        logger.debug('if else starting...')
        logger.debug(f'yj_rule_t: {yj_rule_t}')
        logger.debug(f'config_t: {config_t}')
        # if yj_rule has threshold fields
        # if (not update_required) and yj_rule_t and yj_rule_t.get('field') is not None and yj_rule_t.get('value') is not None and type(yj_rule_t.get('value')) == int:
        for i in range(1): 
            if (not update_required) and yj_rule_t:
                # if in the rule, field or value under threshold are empty or null, then rule is not rate based.
                if yj_rule_t.get('field') is None or yj_rule_t.get('value') is None: break
                if yj_rule_t.get('field') is not None and yj_rule_t.get('value') is not None and type(yj_rule_t.get('value')) == int: 
                # if threshold is defined in rule
                    temp = yj_rule_t
                    update_required = True
                    logger.debug('rule threshold set...')
            # elif (not update_required) and config_t and config_t.get('field') and (not config_t.get('field') == '') and config_t.get('value') and type(config_t.get('value')) == int: 
            elif (not update_required) and config_t and config_t.get('field') is not None and config_t.get('value') is not None and type(config_t.get('value')) == int: 
            # elif (not update_required) and config_t and config_t.get('value') and type(config_t.get('value')) == int: 
                # if threshold is defined in siegma config
                temp = config_t
                update_required = True
                logger.debug('config threshold set...')
            else: logger.debug('temp is empty...')
        if update_required:
            # change field name to ECS format and update rate threshold in config
            ecs_field = ''
            # handle empty field gracefully
            # t = temp.get('field')
            # logger.debug(f'temp.field: {t}')
            # try to convert threshold field to sigma mapped field.
            if temp.get('field') and temp.get('field') != '' and sigma_config.get('fieldmappings').get(temp.get('field')) is not None: ecs_field = sigma_config.get('fieldmappings').get(temp.get('field'))
            # if conversion fails, then consider whatever value was in the threshold.field as ecs formatted and move forward with that
            else: ecs_field = temp.get('field')
            config['threshold'] = {
                'field' : ecs_field,
                'value': temp.get('value')
            }
            config['type'] = 'threshold'
        else: 
            # if deafult config has threshold in it, then delete threshold key entirely if no changes were made
            if config.get('threshold'): del config['threshold']
    except Exception as e:
        logger.error(f'Exception {e} occurred in rate_based_rule_settings()...')
    logger.info('rate_based_rule_settings() finished successfully...')
    return config


# def get_notes(notes_folder, config_n, yj_rule_n, logger):
def get_notes(notes_folder, yj_rule_n, logger):
    ret = ''
    file_name = ''
    try:
        # if type(config_n) == str and config_n != "": 
        #     config_n = [config_n]
        # config_n = [get_slash_set_path(i) for i in config_n]
        if type(yj_rule_n) == str and yj_rule_n != "": 
            yj_rule_n = [yj_rule_n]
            yj_rule_n = [get_slash_set_path(i) for i in yj_rule_n]
        update_required = False
        if (not update_required) and yj_rule_n and type(yj_rule_n) == list and len(yj_rule_n) > 0:
            file_name = yj_rule_n
            update_required = True
            logger.debug('File name set from rule...')
        # elif (not update_required) and config_n and type(config_n) == list and len(config_n) > 0:
        #     file_name = config_n
        #     update_required = True
        #     logger.debug('File name set from config...')
        else: logger.debug('File name not set...')
        if update_required:
            # add forward/back slash to end of folder name
            if notes_folder and len(notes_folder) > 0 and notes_folder[-1] != get_slashes(): notes_folder += get_slashes()
            # remove forward/back slash from start of file name
            if file_name and len(file_name) > 0 and type(file_name) == list:
                for i in file_name:
                    if i[0] == get_slashes(): i = i[1:]
                    with open(get_slash_set_path(notes_folder + i)) as input_file:
                        ret += input_file.read()
                        ret += "\n"
                        print(ret)
    except Exception as e:
        logger.error(f'Exception {e} occurred in get_notes()...')
        return ret
    logger.info(f'get_notes() finished successfully...')
    return ret


def find_d2_kv_in_d1(d1, d2):
    for k2, v2 in d2.items():
        if k2 in d1:
            d1[k2] = v2
    return d1


def add_new_items_to_config(shared_config, rule_config, logger):
    if 'settings' in rule_config: 
        shared_config = find_d2_kv_in_d1(shared_config, rule_config.get('settings'))
    logger.info('add_new_items_to_config() finished successfully...')
    return shared_config


# def get_value_from_co_dict(c, o, c_key, sub_o):
#     ret = None
#     if o and sub_o in o and o.get(sub_o): ret = o.get(sub_o)
#     else: ret = c.get(c_key)
#     return ret


def get_azure_severity(severity):
    ret = None
    allowed_severity = ['high', 'medium', 'low', 'informational']
    if severity.lower() in allowed_severity:
        ret = severity
    elif severity.lower() == 'critical':
        ret = 'high'
    else: ret = 'informational'
    return ret


def list_to_str(item, logger):
    ret = None
    try:
        if type(item) == list:
            logger.debug('{} is a list...'.format(item))
            ret = '\n'.join(item)
        elif type(item) == str:
            logger.debug('{} is an str...'.format(item))
            ret = item
        else:
            logger.debug('{} is an unknown type...'.format(item))
            ret = item
    except Exception as e:
        logger.error('Exception {} occurred in list_to_str()...'.format(e))
    return ret


def create_rule(siegma_config, notes_folder, config, sigma_config, credentials, query, yj_rule, attack, output, script_dir, logger, testing=False):
    logger.info('Starting create_rule()...')
    rule_file = None
    rule_content = None
    try:
        # logger.debug('config:')
        # logger.debug(config)
        # logger.debug('query:')
        # pprint(query)
        # logger.debug(type(query))
        # # set siegma config as per config defined in rule
        config = add_new_items_to_config(config, yj_rule.get('siegma').get('config'), logger) if 'siegma' in yj_rule and 'config' in yj_rule.get('siegma') else config
        # unset sigma original default values
        # query['queryPeriod'] = ''
        # query['queryFrequency'] = ''
        # query['triggerOperator'] = ''
        # query['triggerThreshold'] = ''
        # query['suppressionDuration'] = ''
        # query['suppressionEnabled'] = ''


        # set query quotes
        # query['query'] = query['query'].replace('\"', "'")
        # query['query'] = query['query'].replace('(', "")
        # query['query'] = query['query'].replace(')', "")
        # set severity
        query['severity'] = get_azure_severity(query['severity'])
        # set queryPeriod
        query['queryPeriod'] = config.get('queryPeriod')
        # set queryFrequency
        query['queryFrequency'] = config.get('queryFrequency')
        # set triggerOperator
        query['triggerOperator'] = config.get('triggerOperator')
        # set triggerThreshold
        query['triggerThreshold'] = config.get('triggerThreshold')
        # set suppressionDuration
        query['suppressionDuration'] = config.get('suppressionDuration')
        # set suppressionEnabled
        query['suppressionEnabled'] = config.get('suppressionEnabled')

        # update displayName
        query['displayName'] = get_author_name(query['displayName'], yj_rule.get('author'), logger)
        
        ######### description updates ##########################
        # merge author in description
        query['description'] += '' if yj_rule.get('author') is None else '\n\n# Author:\n\n' + list_to_str(yj_rule.get('author'), logger)
        # merge falsepositives in tags
        query['description'] += '' if yj_rule.get('tags') is None else '\n\n# MITRE ATT&CK Tags:\n\n' + list_to_str(yj_rule.get('tags'), logger)
        # merge notes in description
        # query['description'] += '\n\nADS/Notes:\n\n' + get_notes(notes_folder, config.get('note'), yj_rule.get('note'), logger)
        query['description'] += '' if yj_rule.get('note') is None else '\n\n# ADS/Notes:\n\n' + get_notes(notes_folder, yj_rule.get('note'), logger)
        # merge falsepositives in description
        query['description'] += '' if yj_rule.get('falsepositives') is None else '\n\n# False Positives:\n\n' + list_to_str(yj_rule.get('falsepositives'), logger)
        # merge references in description
        query['description'] += '' if yj_rule.get('references') is None else '\n\n# References:\n\n' + list_to_str(yj_rule.get('references'), logger)
        ####################################################

        rule_content = {
                'kind': config.get('kind'),
                'etag': '*',
                'properties': query
            }

        #############
        logger.info('Final rule_content:')
        pprint(rule_content)
        rule_file = dump_to_file(rule_content, output=output)
    except Exception as e:
        logger.error(f'Exception {e} occurred in create_rule()...')
    return rule_file
