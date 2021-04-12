import os
import sys
import argparse
from os import listdir
from pprint import pprint
from utils import get_slashes
from os.path import isfile, join


# CheckIfSiegmaCompliant.py
# By Wesley
# https://github.com/wesley587

# global vars
exit_status_value = 0


class parsing:


    def __init__(self, dir):
        self.agg = ['count(', 'min(', 'max(', 'avg(', 'sum(']
        self.dir = dir


    def firstParsing(self, folders):
        # if string then this means that this a single file needs to be checked for compliance
        if type(folders) == str:
            folders = [folders]
            self.Parsing_file(folders)
        # else whole folders
        else:
            for folder in folders:
                path = get_slashes().join([self.dir, folder])
                files = [x for x in listdir(path) if isfile(join(path, x))]
                # pprint(files)
                f = [x for x in listdir(path) if not isfile(join(path, x))]
                # pprint(f)
                if len(files) > 0:
                    self.Parsing_files(files, path)
                if len(f) > 0:
                    self.Parsing_folders(folder, f)


    def Parsing_file(self, file):
        global exit_status_value
        error = dict()
        for x in file:
            yaml_file = open(x, 'r', encoding='utf8')
            detect_count = 0
            local = x
            error[local] = list()
            for k in yaml_file:
                if 'detection:' in k:
                    detect_count += 1
                if 'condition:' in k:
                    for x in self.agg:
                        if x in k:
                            x = x.replace('(', '')
                            error[local].append(f'\t* An unsupported Aggregation expression ({x}) is present on the sigma rule.')

            if detect_count > 1:
                error[local].append('\t* There is more than 1 instance of detection on this sigma rule.')
        for k, v in error.items():
            if len(v) > 0:
                exit_status_value = 1
                print(f'ERROR FOUND - Sigma Rule: {k}')
                for x in v:
                    print(x)
                print("\n")


    def Parsing_files(self, files, path):
        global exit_status_value
        error = dict()
        for x in files:
            yaml_file = open(get_slashes().join([path, x]), 'r', encoding='utf8')
            detect_count = 0
            local = get_slashes().join([path, x])
            error[local] = list()
            for k in yaml_file:
                if 'detection:' in k:
                    detect_count += 1
                if 'condition:' in k:
                    for x in self.agg:
                        if x in k:
                            x = x.replace('(', '')
                            error[local].append(f'\t* An unsupported Aggregation expression ({x}) is present on the sigma rule.')

            if detect_count > 1:
                error[local].append('\t* There is more than 1 instance of detection on this sigma rule.')
        for k, v in error.items():
            if len(v) > 0:
                exit_status_value = 1
                print(f'ERROR FOUND - Sigma Rule: {k}')
                for x in v:
                    print(x)
                print("\n")


    def Parsing_folders(self, path, folder):
        for o in folder:
            path2 = get_slashes().join([self.dir, path, o])
            files2 = [x for x in listdir(path2) if isfile(join(path2, x))]
            self.Parsing_files(files2, path2)


def get_slashes():
    ret = '\\'
    if os.name != 'nt': 
        ret = '/'
        # print('Non-windows machine...')
    # else:
    #     print('Windows machine...')
    # print('Returning {}...'.format(ret))
    return ret


def main():
    parse = argparse.ArgumentParser()
    parse.add_argument('-p', help='Parsing the sigma rules in a Directory')
    path = vars(parse.parse_args())
    dir = path['p']
    folders = ''
    # for single file
    if isfile(dir): 
        file = dir
        start = parsing(dir=file)
        start.firstParsing(file)
    # for folders
    else: 
        folders = [x for x in listdir(dir) if not isfile(join(dir, x))]
        if folders == []: 
            # if single folder with n files
            folders = [x for x in listdir(dir) if isfile(join(dir, x))]
            start = parsing(dir=dir)
            start.Parsing_files(folders, dir)
        else:
            start = parsing(dir=dir)
            start.firstParsing(folders)
        # pprint(folders)
    sys.exit(exit_status_value)


main()