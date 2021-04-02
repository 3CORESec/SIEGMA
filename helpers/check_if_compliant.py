from os import listdir
from os.path import isfile, join
import argparse

# CheckIfSiegmaCompliant.py
# By Wesley
# https://github.com/wesley587


class parsing:
    def __init__(self, dir):
        self.agg = ['count(', 'min(', 'max(', 'avg(', 'sum(']
        self.dir = dir

    def firstParsing(self, folders):
        for folder in folders:
            path = '/'.join([self.dir, folder])
            files = [x for x in listdir(path) if isfile(join(path, x))]
            f = [x for x in listdir(path) if not isfile(join(path, x))]
            if len(files) > 0:
                self.Parsing_files(files, path)
            if len(f) > 0:
                self.Parsing_folders(folder, f)

    def Parsing_files(self, files, path):
        error = dict()
        for x in files:
            yaml_file = open('/'.join([path, x]), 'r', encoding='utf8')
            detect_count = 0
            local = '/'.join([path, x])
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
                print(f'ERROR FOUND - Sigma Rule: {k}')
                for x in v:
                    print(x)
                print("\n")

    def Parsing_folders(self, path, folder):
        for o in folder:
            path2 = '/'.join([self.dir, path, o])
            files2 = [x for x in listdir(path2) if isfile(join(path2, x))]
            self.Parsing_files(files2, path2)


if __name__ == '__main__':
    parse = argparse.ArgumentParser()
    parse.add_argument('-p', help='Parsing the sigma rules in a Directory')
    path = vars(parse.parse_args())
    dir = path['p']
    folders = [x for x in listdir(dir) if not isfile(join(dir, x))]
    start = parsing(dir=dir)
    start.firstParsing(folders)