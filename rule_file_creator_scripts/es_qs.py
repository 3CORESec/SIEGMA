import re
import copy
import json
from pprint import pprint


def get_author_name(yj_rule):
    ret = None
    if type(yj_rule) == list:
        ret = yj_rule
    elif type(yj_rule) == str:
        ret = [yj_rule]
    else: ret = list(yj_rule)
    return ret


def dump_to_file(dictionary, output='.output.ndjson'):
    with open(output, "a") as outfile:
        json.dump(dictionary, outfile)
        outfile.write('\n')
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
    return is_technique_boolean, technique


def get_technique_from_mitre(attack, technique_id):
    print('Starting get_technique_from_mitre()...')
    ret = {
        'id': '',
        'name': '',
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
        # So only non-empty and valid tatics and techniques make it to the final output
        if temp2.get('tactic') != {} and temp2.get('technique') != [] and temp2.get('tactic').get('id') != '':
            ret.append(temp2)
    # pprint(temp)
    pprint(ret)
    return ret


def create_rule(config, query, yj_rule, attack, output, logger):
    logger.info('Starting create_es_qs_rule()...')
    rule_file = None
    logger.debug(config)
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
    config['risk_score'] = get_risk_score(yj_rule.get('level'))
    # tags set
    config['tags'] = get_tags(yj_rule.get('logsource').get('service') if yj_rule.get('logsource') and yj_rule.get('logsource').get('service') else 'None')
    # MITRE settings
    if yj_rule.get('tags'): config['threat'] = get_mitre_ttps(attack, yj_rule.get('tags'))
    # rule ID set
    config['rule_id'] = config['id'] = yj_rule.get('id')
    # time set
    config['from'] = 'now-' + yj_rule.get('detection').get('timeframe') if 'timeframe' in yj_rule.get('detection') else ''
    #############
    logger.info('Final config:')
    pprint(config)
    rule_file = dump_to_file(config, output=output)
    return rule_file