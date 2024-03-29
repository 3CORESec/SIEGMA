import re
import requests


class MitreAttack:
    

    tactics = {
        "Reconnaissance": "https://attack.mitre.org/tactics/TA0043",
        "Resource Development": "https://attack.mitre.org/tactics/TA0042",
        "Initial Access": "https://attack.mitre.org/tactics/TA0001",
        "Execution": "https://attack.mitre.org/tactics/TA0002",
        "Persistence": "https://attack.mitre.org/tactics/TA0003",
        "Privilege Escalation": "https://attack.mitre.org/tactics/TA0004",
        "Defense Evasion": "https://attack.mitre.org/tactics/TA0005",
        "Credential Access": "https://attack.mitre.org/tactics/TA0006",
        "Discovery": "https://attack.mitre.org/tactics/TA0007",
        "Lateral Movement": "https://attack.mitre.org/tactics/TA0008",
        "Collection": "https://attack.mitre.org/tactics/TA0009",
        "Command and Control": "https://attack.mitre.org/tactics/TA0011",
        "Exfiltration": "https://attack.mitre.org/tactics/TA0010",
        "Impact": "https://attack.mitre.org/tactics/TA0040"
    }
    techniques = None
    to_be_lowered_chrs = ['and']


    def get_tactics_name_set(self, yj_rule_tags):
        ret = set()
        for tag in yj_rule_tags:
            is_tactic_boolean, tactic = self.is_tactic(tag)
            is_technique_boolean, technique = self.is_technique(tag)
            if is_tactic_boolean and (not is_technique_boolean):
                print('tactic found...')
                ret.add(tactic.get('name'))
        return list(ret)


    def is_tactic(self, item):
        print('Starting is_tactic()...')
        is_tactic_boolean = False
        tactic = {}
        match_list = re.findall(r'^attack\.\w{5,}.*$', item)
        if item.count('.') > 1: match_list = []
        # print(match_list)
        if len(match_list) > 0:
            print(match_list)
            is_tactic_boolean = True
            # print('up')
            # input('')
            tactic = self.get_tactic_from_name(item)    
            #     tactic = get_tactic_from_mitre(attack, item.replace('attack.', '').replace('_', ' '))
            # print('down')
            # input('')
        print('tactic item {} data:'.format(item))
        print(tactic)
        return is_tactic_boolean, tactic


    def is_technique(self, item):
        print('Starting is_technique()...')
        is_technique_boolean = False
        technique = {}
        match_list = re.findall(r'^attack\.t\d{4,}((\.\d{3,})*)$', item)
        print(match_list)
        if len(match_list) > 0:
            print(match_list)
            is_technique_boolean = True
            technique = self.get_technique_from_id(item)
            # technique = get_technique_from_mitre(attack, item.replace('attack.', ''), logger)
            # if technique: is_technique_boolean = True
        print('technique item {} data:'.format(item))
        print(technique)
        return is_technique_boolean, technique


    def format_tactic_name(self, tactic_name):
        try:
            temp = ''
            if '.' in tactic_name:
                # for tactic_names like attack.tactic to tactic
                tactic_name = tactic_name.split('.')[1]
            if '_' in tactic_name:
                # for tactic_names like tactic_name to tactic name
                tactic_name = tactic_name.replace('_', ' ')
            for tactic_chr in tactic_name.split(' '):
                # for tactic_names like tactic name to Tactic Name
                temp += tactic_chr.capitalize() + ' '
            tactic_name = temp.rstrip(' ')
            for tblc in self.to_be_lowered_chrs:
                if tblc in tactic_name.lower():
                    tactic_name = tactic_name.replace(tblc.capitalize(), tblc)
        except Exception as e:
            print('Exception {} occurred in format_tactic_name() for tactic_name {}...'.format(e, tactic_name))
        print('Returning tactic_name {}...'.format(tactic_name))
        return tactic_name


    def get_tactic_id_from_url(self, tactic_url):
        return tactic_url.split('/')[-1]


    def get_tactic_id_from_name(self, tactic_name):
        return self.tactics.get(tactic_name).split('/')[-1]


    def get_tactic_from_name(self, tactic_name):
        try:
            # print('line 1')
            tactic_name = self.format_tactic_name(tactic_name)
            # print('line 2')
            tactic_url = self.tactics.get(tactic_name)
            return {
                'id': self.get_tactic_id_from_url(tactic_url),
                'name': tactic_name,
                'reference': tactic_url
            }
        except Exception as e:
            print('Exception {} occurred in get_tactic_from_name() for tactic_name {}'.format(e, tactic_name))


    def format_technique_id(self, technique_id):
        if 'attack.' in technique_id:
            # for tactic_names like attack.tXXX to tXXX
            technique_id = technique_id.split('attack.')[1]
        technique_id = technique_id.capitalize()
        return technique_id


    def get_technique_name_from_url(self, technique_url, technique_id):
        #         <title>Application Layer Protocol: Web Protocols, Sub-technique T1071.001 - Enterprise | MITRE ATT&CK&reg;</title>
        # <title>Application Layer Protocol, Technique T1071 - Enterprise | MITRE ATT&CK&reg;</title>
        technique_name = 'Unknown Technique'
        for line in (requests.get(technique_url).text).split('\n'):
            if technique_id in line:
                if '.' in technique_id:
                    # if sub technique
                    technique_name = line[line.index('>') + 1 : line.index(technique_id) - 16]
                else:
                    # if technique
                    technique_name = line[line.index('>') + 1 : line.index(technique_id) - 12]
                break
        return technique_name


    def get_technique_from_id(self, technique_id):
        technique_id = self.format_technique_id(technique_id)
        technique_url = "https://attack.mitre.org/techniques/{}/".format(technique_id.replace('.', '/'))
        return {
            'id': technique_id,
            'name': self.get_technique_name_from_url(technique_url, technique_id),
            'reference': technique_url
            }
