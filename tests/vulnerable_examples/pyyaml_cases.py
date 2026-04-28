import yaml
import base64
from yaml import load as yaml_load
from yaml import SafeLoader


data_1 = input()
yaml.load(data_1)

data_2 = input()
tmp_2 = data_2
yaml.load(tmp_2)

data_3 = input()
payload_3 = base64.b64decode(data_3)
yaml.load(payload_3)

data_4 = input()
yaml.unsafe_load(data_4)

data_5 = input()
yaml_load(data_5)

data_6 = input()
yaml.load(data_6, Loader=yaml.SafeLoader)  # safe

data_7 = input()
yaml.load(data_7, Loader=SafeLoader)  # safe

data_8 = input()
yaml.safe_load(data_8)  # safe


def get_payload_9():
    return input()

data_9 = get_payload_9()
yaml.load(data_9)


def deserialize_10(value):
    return yaml.load(value)

data_10 = input()
deserialize_10(data_10)