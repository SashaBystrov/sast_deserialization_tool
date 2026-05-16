import pickle
import pickle as pi
from pickle import loads
from pickle import load as pickle_load
import base64
import os


# -------------------------
# BASIC TAINT CASES
# -------------------------

data_1 = input()
pickle.loads(data_1)

pickle.loads(input())


# -------------------------
# IMPORT AND ALIAS CASES
# -------------------------

data_2 = input()
pi.loads(data_2)

data_3 = input()
loads(data_3)

data_4 = input()
pickle_load(data_4)


# -------------------------
# TAINT PROPAGATION CASES
# -------------------------

data_5 = input()
a_5 = data_5
b_5 = a_5
c_5 = b_5
pickle.loads(c_5)

data_6 = input()
payload_6 = base64.b64decode(data_6)
pickle.loads(payload_6)

data_7 = input()
decoded_7 = base64.b64decode(data_7)
payload_7 = str(decoded_7)
pickle.loads(payload_7)

data_10 = input()
pickle.loads(base64.b64decode(data_10))


# -------------------------
# ALTERNATIVE SOURCE CASES
# -------------------------

data_8 = os.getenv("PAYLOAD")
pickle.loads(data_8)


# -------------------------
# FILE-BASED CASES
# -------------------------

file_11 = open("payload.pkl", "rb")
pickle.load(file_11)

file_12 = open("payload.pkl", "rb")
f_12 = file_12
pickle.load(f_12)

file_13 = open("payload.pkl", "rb")
pi.load(file_13)


# -------------------------
# WEB-LIKE CASES
# -------------------------

def flask_case_14(request):
    data_14 = request.data
    return pickle.loads(data_14)


def flask_case_15(request):
    data_15 = request.get_json()
    return pickle.loads(data_15)


# -------------------------
# INTERPROCEDURAL CASES
# -------------------------

def deserialize_16(value):
    return pickle.loads(value)

data_16 = input()
deserialize_16(data_16)


def get_payload_17():
    return input()

data_17 = get_payload_17()
pickle.loads(data_17)


def normalize_18(value):
    return value

data_18 = input()
payload_18 = normalize_18(data_18)
pickle.loads(payload_18)


# -------------------------
# CONTAINER CASES
# -------------------------

data_19 = input()
container_19 = {"payload": data_19}
pickle.loads(container_19["payload"])

data_20 = input()
container_20 = [data_20]
pickle.loads(container_20[0])


# -------------------------
# SAFE CASES
# -------------------------

data_21 = input()
data_21 = b"safe_payload"
pickle.loads(data_21)

safe_22 = b"constant_payload"
pickle.loads(safe_22)

safe_23 = pickle.dumps({"role": "user"})
pickle.loads(safe_23)

pickle.loads(b"constant_payload")


# -------------------------
# CONDITIONAL CASES
# -------------------------

flag_25 = True
if flag_25:
    data_25 = input()
else:
    data_25 = b"safe"

pickle.loads(data_25)

flag_26 = True
if flag_26:
    data_26 = b"safe_1"
else:
    data_26 = b"safe_2"

pickle.loads(data_26)