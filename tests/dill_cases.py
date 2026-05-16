import dill
import dill as dl
from dill import loads as dill_loads
import base64
import os


# -------------------------
# BASIC TAINT CASES
# -------------------------

data_1 = input()
dill.loads(data_1)

dill.loads(input())


# -------------------------
# IMPORT AND ALIAS CASES
# -------------------------

data_2 = input()
dl.loads(data_2)

data_3 = input()
dill_loads(data_3)


# -------------------------
# TAINT PROPAGATION CASES
# -------------------------

data_4 = input()
tmp_4 = data_4
dill.loads(tmp_4)

data_5 = input()
payload_5 = base64.b64decode(data_5)
dill.loads(payload_5)

data_6 = input()
decoded_6 = base64.b64decode(data_6)
payload_6 = bytes(decoded_6)
dill.loads(payload_6)

data_7 = input()
dill.loads(base64.b64decode(data_7))


# -------------------------
# ALTERNATIVE SOURCE CASES
# -------------------------

data_8 = os.getenv("PAYLOAD")
dill.loads(data_8)


# -------------------------
# INTERPROCEDURAL CASES
# -------------------------

def get_payload_9():
    return input()

data_9 = get_payload_9()
dill.loads(data_9)


def normalize_10(value):
    return value

data_10 = input()
payload_10 = normalize_10(data_10)
dill.loads(payload_10)


def deserialize_11(value):
    return dill.loads(value)

data_11 = input()
deserialize_11(data_11)


def deserialize_second_arg_12(prefix, payload):
    return dill.loads(payload)

safe_prefix_12 = "safe"
data_12 = input()
deserialize_second_arg_12(safe_prefix_12, data_12)


# -------------------------
# CONTAINER CASES
# -------------------------

data_13 = input()
container_13 = {"payload": data_13}
dill.loads(container_13["payload"])

data_14 = input()
container_14 = [data_14]
dill.loads(container_14[0])


# -------------------------
# SAFE CASES
# -------------------------

safe_15 = b"constant_payload"
dill.loads(safe_15)

data_16 = input()
data_16 = b"safe_payload"
dill.loads(data_16)


def get_safe_payload_17():
    return b"constant_payload"

data_17 = get_safe_payload_17()
dill.loads(data_17)


def deserialize_safe_18(value):
    return dill.loads(value)

safe_18 = b"constant_payload"
deserialize_safe_18(safe_18)


# -------------------------
# CONDITIONAL CASES
# -------------------------

flag_19 = True
if flag_19:
    data_19 = input()
else:
    data_19 = b"safe"

dill.loads(data_19)

flag_20 = True
if flag_20:
    data_20 = b"safe_1"
else:
    data_20 = b"safe_2"

dill.loads(data_20)