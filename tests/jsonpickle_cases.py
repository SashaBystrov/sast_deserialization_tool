import jsonpickle
import jsonpickle as jp
from jsonpickle import decode as jsonpickle_decode
import base64
import os


# -------------------------
# BASIC TAINT CASES
# -------------------------

data_1 = input()
jsonpickle.decode(data_1)

data_2 = input()
jsonpickle.loads(data_2)

jsonpickle.decode(input())


# -------------------------
# IMPORT AND ALIAS CASES
# -------------------------

data_3 = input()
jp.decode(data_3)

data_4 = input()
jsonpickle_decode(data_4)


# -------------------------
# TAINT PROPAGATION CASES
# -------------------------

data_5 = input()
tmp_5 = data_5
jsonpickle.decode(tmp_5)

data_6 = input()
payload_6 = base64.b64decode(data_6)
jsonpickle.decode(payload_6)

data_7 = input()
decoded_7 = base64.b64decode(data_7)
payload_7 = str(decoded_7)
jsonpickle.loads(payload_7)

data_8 = input()
jsonpickle.decode(base64.b64decode(data_8))


# -------------------------
# ALTERNATIVE SOURCE CASES
# -------------------------

data_9 = os.getenv("PAYLOAD")
jsonpickle.decode(data_9)


# -------------------------
# INTERPROCEDURAL CASES
# -------------------------

def get_payload_10():
    return input()

data_10 = get_payload_10()
jsonpickle.decode(data_10)


def normalize_11(value):
    return value

data_11 = input()
payload_11 = normalize_11(data_11)
jsonpickle.decode(payload_11)


def deserialize_12(value):
    return jsonpickle.decode(value)

data_12 = input()
deserialize_12(data_12)


def deserialize_second_arg_13(prefix, payload):
    return jsonpickle.decode(payload)

safe_prefix_13 = "safe"
data_13 = input()
deserialize_second_arg_13(safe_prefix_13, data_13)


# -------------------------
# CONTAINER CASES
# -------------------------

data_14 = input()
container_14 = {"payload": data_14}
jsonpickle.decode(container_14["payload"])

data_15 = input()
container_15 = [data_15]
jsonpickle.loads(container_15[0])


# -------------------------
# SAFE CASES
# -------------------------

safe_16 = '{"safe": true}'
jsonpickle.decode(safe_16)

data_17 = input()
data_17 = '{"safe": true}'
jsonpickle.decode(data_17)


def get_safe_payload_18():
    return '{"safe": true}'

data_18 = get_safe_payload_18()
jsonpickle.decode(data_18)


def deserialize_safe_19(value):
    return jsonpickle.decode(value)

safe_19 = '{"safe": true}'
deserialize_safe_19(safe_19)


# -------------------------
# CONDITIONAL CASES
# -------------------------

flag_20 = True
if flag_20:
    data_20 = input()
else:
    data_20 = '{"safe": true}'

jsonpickle.decode(data_20)

flag_21 = True
if flag_21:
    data_21 = '{"safe": true}'
else:
    data_21 = '{"also_safe": true}'

jsonpickle.decode(data_21)