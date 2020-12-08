import os
import re
import copy
import json
import subprocess
from pprint import pprint
from helpers.utils import get_slash_set_path, get_slashes


def get_author_name(yj_rule):
    ret = None
    if type(yj_rule) == list:
        ret = yj_rule
    elif type(yj_rule) == str:
        ret = [yj_rule]
    else: ret = list(yj_rule)
    return ret


def dump_to_file(dictionary, output='.output.ndjson'):
    try:
        with open(output, "a") as outfile:
            json.dump(dictionary, outfile)
            outfile.write('\n')
    except Exception as e:
        print(f"Exception {e} occurred in dump_to_file()...")
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
    print('Starting get_tactic_from_mitre()...')
    ret = {
        'id': '',
        'name': '',
        'reference': ''
    }
    for tactic in attack.enterprise.tactics:
        # print(tactic.name)
        if tactic.name.lower() == item:
            print(tactic.id)
            print(tactic.name)
            print(tactic.wiki)
            ret['id'] = tactic.id
            ret['name'] = tactic.name
            ret['reference'] = tactic.wiki
    return ret


def is_tactic(attack, item):
    print('Starting is_tactic()...')
    is_tactic_boolean = False
    tactic = {}
    match_list = re.findall(r'^attack\.\w{5,}.*$', item)
    print(match_list)
    if len(match_list) > 0:
        print(match_list)
        is_tactic_boolean = True
        tactic = get_tactic_from_mitre(attack, item.replace('attack.', '').replace('_', ' '))
    return is_tactic_boolean, tactic


def get_subtechnique_from_mitre(attack, item):
    print('Starting get_subtechnique_from_mitre()...')
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
    print('Starting is_tactic()...')
    is_subtechnique_boolean = False
    subtechnique = {}
    match_list = re.findall(r'^(attack\.t\d{4,})\.\d+$', item)
    print(match_list)
    if len(match_list) > 0:
        print(match_list)
        is_subtechnique_boolean = True
        subtechnique = get_subtechnique_from_mitre(attack, item.replace('attack.', ''))
    return is_subtechnique_boolean, subtechnique


def get_mitre_ttps(attack, yj_rule):
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
        is_tactic_boolean, tactic = is_tactic(attack, item)
        temp2['tactic'] = tactic
        if is_tactic_boolean:
            idx += 1
            if idx < len(yj_rule) - 1:
                # Read techniques below
                for item2 in yj_rule[idx:]:
                    is_technique_boolean, technique = is_technique(attack, item2)
                    if not is_technique_boolean:
                        # Read subtechniques
                        is_subtechnique_boolean, subtechnique = is_subtechnique(attack, item2)
                        if not is_subtechnique_boolean:
                            break
                        if is_subtechnique_boolean:
                            temp2['technique'].append(subtechnique)    
                    if is_technique_boolean:
                        temp2['technique'].append(technique)
        # So only non-empty and valid tactics and techniques make it to the final output
        if temp2.get('tactic') != {} and temp2.get('technique') != [] and temp2.get('tactic').get('id') != '':
            ret.append(temp2)
    # pprint(temp)
    pprint(ret)
    return ret


def valid_credentials(credentials, logger):
    ret = False
    creds_exist = username_exist = password_exist = url_exist = False
    if credentials and credentials is not None:
        creds_exist = True
        logger.debug('Credentials key exists...')
        logger.debug('Checking further...')
        if 'kibana_username' in credentials:
            if credentials.get('kibana_username') and credentials.get('kibana_username') != '':
                username_exist = True
                logger.debug('Kibana_username exists...')
        if 'kibana_password' in credentials:
            if credentials.get('kibana_password') and credentials.get('kibana_password') != '':
                password_exist = True
                logger.debug('kibana_password exists...')
        if 'kibana_url' in credentials:
            if credentials.get('kibana_url') and credentials.get('kibana_url') != '':
                url_exist = True
                logger.debug('kibana_url exists...')
    if creds_exist and username_exist and password_exist and url_exist:
        ret = True
        logger.info('Existing creds found. Output file shall be uploaded to ELK...')
    else:
        ret = False
        logger.info('No creds found. Output file shall not be uploaded to ELK...')
    return ret


def handle_response_errors(status_code, message, logger):
    if status_code == 400 and 'invalid file extension'.lower() in message.lower():
        logger.error('Use .ndjson as the file extension for output file...')


def install_rules(script_dir, credentials, rule_file, logger):
    # if windows, execute these commands
    curl_path = get_slash_set_path(script_dir + '/helpers/curl/curl.exe')
    logger.debug('Script Dir: {}'.format(curl_path))
    logger.debug('Rule Output File: {}'.format(rule_file))
    result = result_out = None
    query = None
    # if windows machine
    if os.name == 'nt':
        command = 'powershell -nop -c \"{} {};\"'.format(curl_path, "-X POST \"{}/api/detection_engine/rules/_import?overwrite=true\" -u '{}:{}' -H 'kbn-xsrf: true' -H 'Content-Type: multipart/form-data' --form 'file=@{}'".format(credentials.get('kibana_url'), credentials.get('kibana_username'), credentials.get('kibana_password'), rule_file))
        logger.debug('Command: {}'.format(command))
        logger.info('Windows powershell command shall be executed...')
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        result_out = json.loads(result.stdout.decode('utf-8'))
        result_error = result.stderr.decode('utf-8')
        logger.debug(result_out)
        logger.error(result_error)
    # if linux machine
    else:
        command = """curl -X POST "{}/api/detection_engine/rules/_import?overwrite=true" -u '{}:{}' -H 'kbn-xsrf: true' -H 'Content-Type: multipart/form-data' --form "file=@{}" """.format(credentials.get('kibana_url'), credentials.get('kibana_username'), credentials.get('kibana_password'), rule_file)
        logger.debug('Command: {}'.format(command))
        logger.info('Linux shell shall be executed...')
        process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        proc_stdout = process.communicate()[0].strip().decode('utf-8')
        print(proc_stdout)
        result_out = json.loads(proc_stdout)
        logger.debug(result_out)
    logger.info('Import Successful: {}...'.format(result_out.get('success')))
    logger.info('Count Successfully Imported Rules: {}...'.format(result_out.get('success_count')))
    logger.info('Import Errors: {}...'.format(result_out.get('errors')))
    logger.info('Response Message: {}...'.format(result_out.get('message')))
    logger.info('Response status code: {}...'.format(result_out.get('status_code')))
    handle_response_errors(result_out.get('status_code'), result_out.get('message'), logger)
    return query


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
                # if threshold is not defined in siegma config
                    temp = yj_rule_t
                    update_required = True
                    logger.debug('rule threshold set...')
            # elif (not update_required) and config_t and config_t.get('field') and (not config_t.get('field') == '') and config_t.get('value') and type(config_t.get('value')) == int: 
            elif (not update_required) and config_t and config_t.get('field') is not None and config_t.get('value') is not None and type(config_t.get('value')) == int: 
            # elif (not update_required) and config_t and config_t.get('value') and type(config_t.get('value')) == int: 
                # if threshold is not defined in siegma config
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
            if temp.get('field') and temp.get('field') != '': ecs_field = sigma_config.get('fieldmappings').get(temp.get('field'))
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


def get_notes(notes_folder, config_n, yj_rule_n, logger):
    ret = ''
    file_name = ''
    if type(config_n) == str and config_n != "": 
        config_n = [config_n]
    config_n = [get_slash_set_path(i) for i in config_n]
    if type(yj_rule_n) == str and yj_rule_n != "": 
        yj_rule_n = [yj_rule_n]
        yj_rule_n = [get_slash_set_path(i) for i in yj_rule_n]
    update_required = False
    try:
        if (not update_required) and yj_rule_n and type(yj_rule_n) == list and len(yj_rule_n) > 0:
            file_name = yj_rule_n
            update_required = True
            logger.debug('File name set from rule...')
        elif (not update_required) and config_n and type(config_n) == list and len(config_n) > 0:
            file_name = config_n
            update_required = True
            logger.debug('File name set from config...')
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


def add_new_items_to_config(shared_config, rule_config):

    return shared_config


def create_rule(notes_folder, config, sigma_config, credentials, query, yj_rule, attack, output, script_dir, logger, testing=False):
    logger.info('Starting create_es_qs_rule()...')
    rule_file = None
    try:
        logger.debug(config)
        # # set siegma config as per config defined in rule
        config = add_new_items_to_config(config, yj_rule.get('siegma').get('config')) if 'siegma' in yj_rule and 'config' in yj_rule.get('siegma') else config
        # set query
        config['query'] = query
        # set author name
        config['author'] = config.get('author') if not (config.get('author') is None or config.get('author') == '' or config.get('author') == []) else get_author_name(yj_rule.get('author'))
        # name set
        config['name'] = yj_rule.get('title')
        # description set
        config['description'] = yj_rule.get('description')
        # falsepositives set
        if yj_rule.get('falsepositives'): config['false_positives'] = yj_rule.get('falsepositives')
        # references set
        if yj_rule.get('references'): config['references'] = yj_rule.get('references')
        # severity set
        config['severity'] = yj_rule.get('level')
        # risk score set
        config['risk_score'] = get_risk_score(yj_rule.get('level')) if 'score' not in yj_rule else yj_rule.get('score')
        # tags set
        config['tags'] = yj_rule.get('siemtags') if yj_rule and 'siemtags' in yj_rule and type(yj_rule.get('siemtags')) == list else []
        # MITRE settings
        if yj_rule.get('tags'): config['threat'] = get_mitre_ttps(attack, yj_rule.get('tags'))
        # rule ID set
        config['rule_id'] = config['id'] = yj_rule.get('id')
        # time set
        if 'timeframe' in yj_rule.get('detection'): config['from'] = 'now-' + yj_rule.get('detection').get('timeframe')
        # rate_based_rule
        config = rate_based_rule_settings(sigma_config, config, config.get('threshold'), yj_rule.get('threshold'), logger)
        # investigation notes
        config['note'] = get_notes(notes_folder, config.get('note'), yj_rule.get('note'), logger)
        #############
        logger.info('Final config:')
        pprint(config)
        rule_file = dump_to_file(config, output=output)
    except Exception as e:
        logger.error(f'Exception {e} occurred in create_rule()...')
    return rule_file