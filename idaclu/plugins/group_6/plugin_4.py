import collections
import json
import re
#
import idautils
import idaapi
import idc
#
from idaclu import ida_shims
from idaclu import ida_utils
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Function Argument Consistency')
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = [('checkbox', 'call_types', ['Inconsistent Prototypes', 'Consistent Prototypes'])]


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
    
    is_x_add = plug_params['call_types'][0][1]
    is_v_add = plug_params['call_types'][1][1]

    merged_calls = collections.defaultdict(dict)
    for func_addr in func_gen():
        func_calls = ida_utils.extract_calls_from_decompiled(func_addr)
        for callee_addr, call_descs in func_calls.items():  # call_descs = [(pos, args)]
            if idaapi.get_func(callee_addr):
                merged_calls[callee_addr].update(call_descs)
        
    for callee_addr, call_descs in merged_calls.items():  # 18446744073709551615
        is_consistent = True
        temp = {}
        temp[callee_addr] = []

        def_args = ida_utils.get_func_params(callee_addr)
        for i, (call_pos, call_args) in enumerate(call_descs.items()):
            call_func = idaapi.get_func(call_pos)  # 18446744073709551615
            args_line = ', '.join("{} {}".format(arg['type'], arg['name']) for arg in call_args)
            temp[callee_addr].append((call_func.start_ea, args_line))
            
            if is_consistent == True:
                if len(def_args) == len(call_args):
                    for i in range(len(def_args)):
                        if def_args[i]['type'] != call_args[i]['type']:
                            is_consistent = False
                            break
                else:
                    is_consistent = False
         
        if ((is_x_add == True and is_v_add == True) or 
            (is_v_add == True and is_consistent == True) or 
            (is_x_add == True and is_consistent == False)):
            callee_name = idc.get_func_name(callee_addr)
            report['data'][callee_name].extend(temp[callee_addr])
            report['stat'][callee_name] += len(temp[callee_addr])

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
