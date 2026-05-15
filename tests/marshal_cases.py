import marshal
import marshal as m
from marshal import loads as marshal_loads
import base64
import os


# -------------------------
# BASIC TAINT CASES
# -------------------------

data_1 = input()
marshal.loads(data_1)

marshal.loads(input())


# -------------------------
# IMPORT AND ALIAS CASES
# -------------------------

data_2 = input()
m.loads(data_2)

data_3 = input()
marshal_loads(data_3)


# -------------------------
# TAINT PROPAGATION CASES
# -------------------------

data_4 = input()
a_4 = data_4
b_4 = a_4
marshal.loads(b_4)

data_5 = input()
decoded_5 = base64.b64decode(data_5)
marshal.loads(decoded_5)

data_6 = input()
decoded_6 = base64.b64decode(data_6)
converted_6 = bytes(decoded_6)
marshal.loads(converted_6)

data_9 = input()
marshal.loads(base64.b64decode(data_9))


# -------------------------
# ALTERNATIVE SOURCE CASES
# -------------------------

data_7 = os.getenv("PAYLOAD")
marshal.loads(data_7)


# -------------------------
# FILE-BASED CASES
# -------------------------

file_10 = open("payload.bin", "rb")
marshal.load(file_10)


# -------------------------
# INTERPROCEDURAL CASES
# -------------------------

def get_payload_12():
    return input()

data_12 = get_payload_12()
marshal.loads(data_12)


def normalize_13(value):
    return value

data_13 = input()
payload_13 = normalize_13(data_13)
marshal.loads(payload_13)


def deserialize_14(value):
    return marshal.loads(value)

data_14 = input()
deserialize_14(data_14)


def get_raw_15():
    return input()

def decode_15(value):
    return base64.b64decode(value)

def run_15(value):
    return marshal.loads(value)

raw_15 = get_raw_15()
decoded_15 = decode_15(raw_15)
run_15(decoded_15)


def deserialize_second_arg_18(prefix, payload):
    return marshal.loads(payload)

safe_prefix_18 = "safe"
data_18 = input()
deserialize_second_arg_18(safe_prefix_18, data_18)


# -------------------------
# CONTAINER CASES
# -------------------------

data_20 = input()
container_20 = {"payload": data_20}
marshal.loads(container_20["payload"])


# -------------------------
# SAFE CASES
# -------------------------

safe_10 = b"safe"
marshal.loads(safe_10)

data_11 = input()
data_11 = b"safe"
marshal.loads(data_11)


def get_safe_16():
    return b"safe"

data_16 = get_safe_16()
marshal.loads(data_16)


def deserialize_17(value):
    return marshal.loads(value)

safe_17 = b"safe"
deserialize_17(safe_17)


# -------------------------
# CONDITIONAL CASES
# -------------------------

flag_19 = True
if flag_19:
    data_19 = input()
else:
    data_19 = b"safe"

marshal.loads(data_19)

flag_21 = True
if flag_21:
    data_21 = b"safe_1"
else:
    data_21 = b"safe_2"

marshal.loads(data_21)