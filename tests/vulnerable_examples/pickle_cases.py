import pickle
import pickle as pi
from pickle import loads
from pickle import load as pickle_load
import base64
import os


# 1. Прямой пользовательский ввод -> pickle.loads
data_1 = input()
pickle.loads(data_1)


# 2. Alias import: import pickle as p
data_2 = input()
pi.loads(data_2)


# 3. From import: from pickle import loads
data_3 = input()
loads(data_3)


# 4. From import with alias: from pickle import load as pickle_load
data_4 = input()
pickle_load(data_4)


# 5. Цепочка присваиваний
data_5 = input()
a_5 = data_5
b_5 = a_5
c_5 = b_5
pickle.loads(c_5)


# 6. Передача через функцию распространения base64.b64decode
data_6 = input()
payload_6 = base64.b64decode(data_6)
pickle.loads(payload_6)


# 7. Несколько функций распространения подряд
data_7 = input()
decoded_7 = base64.b64decode(data_7)
payload_7 = str(decoded_7)
pickle.loads(payload_7)


# 8. Источник os.getenv
data_8 = os.getenv("PAYLOAD")
pickle.loads(data_8)


# 9. Прямой вызов источника внутри sink
pickle.loads(input())


# 10. Прямой вызов propagation function внутри sink
data_10 = input()
pickle.loads(base64.b64decode(data_10))


# 11. pickle.load с open()
file_11 = open("payload.pkl", "rb")
pickle.load(file_11)


# 12. pickle.load с переменной от open()
file_12 = open("payload.pkl", "rb")
f_12 = file_12
pickle.load(f_12)


# 13. pickle.load через alias import
file_13 = open("payload.pkl", "rb")
pi.load(file_13)


# 14. Значение через атрибут request.data
def flask_case_14(request):
    data_14 = request.data
    return pickle.loads(data_14)


# 15. Значение через request.get_json()
def flask_case_15(request):
    data_15 = request.get_json()
    return pickle.loads(data_15)


# 16. Передача tainted-данных через аргумент функции
def deserialize_16(value):
    return pickle.loads(value)

data_16 = input()
deserialize_16(data_16)


# 17. Источник внутри функции
def get_payload_17():
    return input()

data_17 = get_payload_17()
pickle.loads(data_17)


# 18. Пользовательская функция-пропагатор
def normalize_18(value):
    return value

data_18 = input()
payload_18 = normalize_18(data_18)
pickle.loads(payload_18)


# 19. Контейнер: значение внутри словаря
# Для текущей версии может обнаруживаться без поддержки Subscript.
data_19 = input()
container_19 = {"payload": data_19}
pickle.loads(container_19["payload"])


# 20. Контейнер: значение внутри списка
# Для текущей версии может обнаруживаться без поддержки Subscript.
data_20 = input()
container_20 = [data_20]
pickle.loads(container_20[0])


# 21. Перезапись tainted-переменной безопасным значением
# Не должно обнаруживаться.
data_21 = input()
data_21 = b"safe_payload"
pickle.loads(data_21)


# 22. Константные данные
# Не должно обнаруживаться.
safe_22 = b"constant_payload"
pickle.loads(safe_22)


# 23. Данные сформированы внутри программы через pickle.dumps
# Не должно обнаруживаться.
safe_23 = pickle.dumps({"role": "user"})
pickle.loads(safe_23)


# 24. Вызов pickle.loads с литералом напрямую
# Не должно обнаруживаться.
pickle.loads(b"constant_payload")


# 25. Условное присваивание: одна ветка tainted
# ОБНАРУЖИВАЕТСЯ.
flag_25 = True
if flag_25:
    data_25 = input()
else:
    data_25 = b"safe"

pickle.loads(data_25)


# 26. Условное присваивание: обе ветки safe
# Не должно обнаруживаться.
flag_26 = True
if flag_26:
    data_26 = b"safe_1"
else:
    data_26 = b"safe_2"

pickle.loads(data_26)