import marshal_cases
import marshal_cases as m
import base64
import os
from marshal_cases import loads as marshal_loads


# 1. Прямой source → sink
data_1 = input()
marshal.loads(data_1)


# 2. Alias
data_2 = input()
m.loads(data_2)


# 3. from import
data_3 = input()
marshal_loads(data_3)


# 4. Цепочка присваиваний
data_4 = input()
a_4 = data_4
b_4 = a_4
marshal.loads(b_4)


# 5. Propagation
data_5 = input()
decoded_5 = base64.b64decode(data_5)
marshal.loads(decoded_5)


# 6. Несколько propagation
data_6 = input()
decoded_6 = base64.b64decode(data_6)
converted_6 = bytes(decoded_6)
marshal.loads(converted_6)


# 7. ENV source
data_7 = os.getenv("PAYLOAD")
marshal.loads(data_7)


# 8. Прямой вызов source
marshal.loads(input())


# 9. Вложенный propagation
data_9 = input()
marshal.loads(base64.b64decode(data_9))


# 10. Безопасная константа
safe_10 = b"safe"
marshal.loads(safe_10)


# 11. Перезапись taint
data_11 = input()
data_11 = b"safe"
marshal.loads(data_11)


# 12. Межпроцедурный: source в функции
def get_payload_12():
    return input()

data_12 = get_payload_12()
marshal.loads(data_12)


# 13. Пользовательский propagation
def normalize_13(value):
    return value

data_13 = input()
payload_13 = normalize_13(data_13)
marshal.loads(payload_13)


# 14. Sink внутри функции (wrapper)
def deserialize_14(value):
    return marshal.loads(value)

data_14 = input()
deserialize_14(data_14)


# 15. Несколько функций
def get_raw_15():
    return input()

def decode_15(value):
    return base64.b64decode(value)

def run_15(value):
    return marshal.loads(value)

raw_15 = get_raw_15()
decoded_15 = decode_15(raw_15)
run_15(decoded_15)


# 16. Безопасный return из функции
def get_safe_16():
    return b"safe"

data_16 = get_safe_16()
marshal.loads(data_16)


# 17. Wrapper + безопасное значение
def deserialize_17(value):
    return marshal.loads(value)

safe_17 = b"safe"
deserialize_17(safe_17)


# 18. Второй аргумент tainted
def deserialize_second_arg_18(prefix, payload):
    return marshal.loads(payload)

safe_prefix_18 = "safe"
data_18 = input()
deserialize_second_arg_18(safe_prefix_18, data_18)


# 19. Условное присваивание
flag_19 = True
if flag_19:
    data_19 = input()
else:
    data_19 = b"safe"

marshal.loads(data_19)


# 20. Контейнер
data_20 = input()
container_20 = {"payload": data_20}
marshal.loads(container_20["payload"])