import collections
import json
import re
#
import idautils
import idaapi
#
from idaclu import ida_shims
from idaclu import ida_utils
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Function Argument Types')
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = [(
    'checkbox', 'data_types',
    [
        'C Fundamental Types',
        'Windows Data Types',
        'DirectX Data Types',
        'Custom Data Types',
        'Missing Data Types'
    ]
)]


def order_item_len(input_dict):
    def get_len(val):
        fs = val[1]
        if isinstance(fs, int):
            return fs
        elif isinstance(fs, list):
            return len(fs)

    return collections.OrderedDict(sorted(input_dict.items(), key=get_len, reverse=True))

def get_data(func_gen=None, env_desc=None, plug_params=None):

    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    is_std_add = plug_params['data_types'][0][1]
    is_win_add = plug_params['data_types'][1][1]
    is_ddx_add = plug_params['data_types'][2][1]
    is_usr_add = plug_params['data_types'][3][1]
    is_unk_add = plug_params['data_types'][4][1]

    for func_addr in func_gen():
        p_list = []
        proto = ida_utils.get_func_params(func_addr)
        for param in proto:
            p_type = param['type']
            p_name = param['name']

            if p_type in p_list:
                continue

            dt_type = ida_utils.get_dt_type(p_type)

            if ((is_std_add and dt_type == 'std')
                or (is_win_add and dt_type == 'win')
                or (is_ddx_add and dt_type == 'ddx')
                or (is_unk_add and dt_type == 'unk')
                or (is_usr_add and dt_type == 'usr')
               ):
                report['data'][p_type].append((func_addr, p_name))
                report['stat'][p_type] += 1
                p_list.append(p_type)

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
