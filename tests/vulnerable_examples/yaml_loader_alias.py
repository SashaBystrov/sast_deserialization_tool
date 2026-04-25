import yaml

data = input()
yaml.load(data, Loader=yaml.SafeLoader)