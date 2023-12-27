from enum import Enum, auto

TRUSTED_HOSTNAMES = '''
xjtu.app
xjtu.men
xjtu.live
# cf.xjtu.live
# ipv4.xjtu.live
# ipv6.xjtu.live
# us.xjtu.live
# jp.xjtu.live
# hk.xjtu.live
# direct.xjtu.live
'''
TRUSTED_HOSTNAMES = [i.strip() for i in TRUSTED_HOSTNAMES.strip().splitlines()
                     if len(i.strip()) != 0 and not i.strip().startswith('#')]
TRUSTED_HOSTNAMES = set(TRUSTED_HOSTNAMES)

name_of = lambda name, key: f'xjtumen-share-session-{name}-{key}'


class AttrDict(dict):
    __setattr__ = dict.__setitem__
    __getattr__ = dict.__getitem__

class Status(int, Enum):
    PENDING = auto()
    FINISHED = auto()

