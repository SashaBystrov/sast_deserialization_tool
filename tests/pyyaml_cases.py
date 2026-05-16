import yaml
import yaml as y
from yaml import load as yaml_load
from yaml import unsafe_load as yaml_unsafe_load
from yaml import SafeLoader
import base64
import os


# -------------------------
# BASIC TAINT CASES
# -------------------------

data_1 = input()
yaml.load(data_1)

yaml.load(input())


# -------------------------
# IMPORT AND ALIAS CASES
# -------------------------

data_2 = input()
y.load(data_2)

data_3 = input()
yaml_load(data_3)

data_4 = input()
yaml_unsafe_load(data_4)


# -------------------------
# TAINT PROPAGATION CASES
# -------------------------

data_5 = input()
tmp_5 = data_5
payload_5 = tmp_5
yaml.load(payload_5)

data_6 = input()
payload_6 = base64.b64decode(data_6)
yaml.load(payload_6)

data_9 = input()
yaml.load(base64.b64decode(data_9))


# -------------------------
# ALTERNATIVE SOURCE CASES
# -------------------------

data_7 = os.getenv("YAML_PAYLOAD")
yaml.load(data_7)


# -------------------------
# UNSAFE YAML LOADER CASES
# -------------------------

data_10 = input()
yaml.unsafe_load(data_10)

data_11 = input()
yaml.full_load(data_11)


# -------------------------
# INTERPROCEDURAL CASES
# -------------------------

def get_payload_17():
    return input()

data_17 = get_payload_17()
yaml.load(data_17)


def normalize_18(value):
    temp = value
    return temp

data_18 = input()
payload_18 = normalize_18(data_18)
yaml.load(payload_18)


def deserialize_19(value):
    return yaml.load(value)

data_19 = input()
deserialize_19(data_19)


def deserialize_second_arg_20(prefix, payload):
    return yaml.load(payload)

safe_prefix_20 = "safe"
data_20 = input()
deserialize_second_arg_20(safe_prefix_20, data_20)


# -------------------------
# CONTAINER CASES
# -------------------------

data_24 = input()
container_24 = {"payload": data_24}
yaml.load(container_24["payload"])


# -------------------------
# SAFE LOADER CASES
# -------------------------

data_12 = input()
yaml.load(data_12, Loader=yaml.SafeLoader)

data_13 = input()
yaml.load(data_13, Loader=SafeLoader)

data_14 = input()
yaml.safe_load(data_14)


# -------------------------
# SAFE CASES
# -------------------------

safe_15 = "name: test"
yaml.load(safe_15)

data_16 = input()
data_16 = "safe: true"
yaml.load(data_16)


def get_safe_payload_21():
    return "safe: true"

data_21 = get_safe_payload_21()
yaml.load(data_21)


def deserialize_safe_22(value):
    return yaml.load(value)

safe_22 = "safe: true"
deserialize_safe_22(safe_22)


# -------------------------
# CONDITIONAL CASES
# -------------------------

flag_23 = True
if flag_23:
    data_23 = input()
else:
    data_23 = "safe: true"

yaml.load(data_23)

flag_25 = True
if flag_25:
    data_25 = "safe_1: true"
else:
    data_25 = "safe_2: true"

yaml.load(data_25)