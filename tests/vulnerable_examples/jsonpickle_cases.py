import yaml
import os
import base64


# -------------------------
# BASIC TAINT CASES
# -------------------------

# 1. Прямой input → yaml.load
data_1 = input()
yaml.load(data_1)


# 2. Через переменные
data_2 = input()
a_2 = data_2
b_2 = a_2
yaml.load(b_2)


# 3. Через propagation
data_3 = input()
decoded_3 = base64.b64decode(data_3)
yaml.load(decoded_3)


# -------------------------
# SAFE CASES
# -------------------------

# 4. safe_load — безопасно
data_4 = input()
yaml.safe_load(data_4)


# 5. Константа — безопасно
yaml.load("key: value")


# -------------------------
# ATTRIBUTES (Flask-like)
# -------------------------

# 6. request.data
def flask_case_6(request):
    return yaml.load(request.data)


# 7. request.get_json()
def flask_case_7(request):
    data = request.get_json()
    return yaml.load(data)


# -------------------------
# INTERPROCEDURAL
# -------------------------

# 8. Source внутри функции
def get_payload_8():
    return input()

data_8 = get_payload_8()
yaml.load(data_8)


# 9. Sink внутри функции
def deserialize_9(value):
    return yaml.load(value)

data_9 = input()
deserialize_9(data_9)


# 10. Propagation функция
def normalize_10(value):
    return value

data_10 = input()
payload_10 = normalize_10(data_10)
yaml.load(payload_10)


# 11. Цепочка функций
def get_raw_11():
    return input()

def decode_11(v):
    return base64.b64decode(v)

def run_11(v):
    return yaml.load(v)

raw = get_raw_11()
decoded = decode_11(raw)
run_11(decoded)


# -------------------------
# ARGUMENT POSITION
# -------------------------

# 12. tainted аргумент не первый
def wrapper_12(prefix, payload):
    return yaml.load(payload)

data_12 = input()
wrapper_12("safe", data_12)


# -------------------------
# SAFE OVERRIDE
# -------------------------

# 13. перезапись tainted значения
data_13 = input()
data_13 = "safe"
yaml.load(data_13)


# -------------------------
# CONTAINERS
# -------------------------

# 14. taint внутри dict
data_14 = input()
container = {"payload": data_14}
yaml.load(container["payload"])


# -------------------------
# EDGE CASES
# -------------------------

# 15. lambda - НЕНАШЕЛ
data_15 = input()
func = lambda x: x
yaml.load(func(data_15))


# 16. тернарный оператор
data_16 = input()
safe = False
value = data_16 if safe else "safe"
yaml.load(value)


# 17. getattr-like usage (частично поддерживается)
def wrapper_17(obj):
    return yaml.load(obj.data)