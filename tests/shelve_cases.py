import shelve
import shelve as sh
from shelve import open as shelve_open
import os


# -------------------------
# BASIC TAINT CASES
# -------------------------

path_1 = input()
shelve.open(path_1)

shelve.open(input())


# -------------------------
# IMPORT AND ALIAS CASES
# -------------------------

path_2 = input()
sh.open(path_2)

path_3 = input()
shelve_open(path_3)


# -------------------------
# TAINT PROPAGATION CASES
# -------------------------

path_4 = input()
tmp_4 = path_4
shelve.open(tmp_4)


# -------------------------
# ALTERNATIVE SOURCE CASES
# -------------------------

path_5 = os.getenv("SHELVE_PATH")
shelve.open(path_5)


# -------------------------
# INTERPROCEDURAL CASES
# -------------------------

def get_path_6():
    return input()

path_6 = get_path_6()
shelve.open(path_6)


def normalize_path_7(value):
    return value

path_7 = input()
payload_7 = normalize_path_7(path_7)
shelve.open(payload_7)


def open_shelve_8(path):
    return shelve.open(path)

path_8 = input()
open_shelve_8(path_8)


def open_shelve_second_arg_9(prefix, path):
    return shelve.open(path)

safe_prefix_9 = "safe"
path_9 = input()
open_shelve_second_arg_9(safe_prefix_9, path_9)


# -------------------------
# CONTAINER CASES
# -------------------------

path_10 = input()
container_10 = {"path": path_10}
shelve.open(container_10["path"])

path_11 = input()
container_11 = [path_11]
shelve.open(container_11[0])


# -------------------------
# SAFE CASES
# -------------------------

safe_12 = "local.db"
shelve.open(safe_12)

path_13 = input()
path_13 = "local.db"
shelve.open(path_13)


def get_safe_path_14():
    return "local.db"

path_14 = get_safe_path_14()
shelve.open(path_14)


def open_safe_shelve_15(path):
    return shelve.open(path)

safe_15 = "local.db"
open_safe_shelve_15(safe_15)


# -------------------------
# CONDITIONAL CASES
# -------------------------

flag_16 = True
if flag_16:
    path_16 = input()
else:
    path_16 = "local.db"

shelve.open(path_16)

flag_17 = True
if flag_17:
    path_17 = "local_1.db"
else:
    path_17 = "local_2.db"

shelve.open(path_17)