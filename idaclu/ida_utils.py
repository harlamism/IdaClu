import collections
import re
#
import idc
import idaapi
import idautils
import ida_hexrays

# new backward-incompatible modules
try:
    import ida_dirtree
    from ssdeep import (
        hash as ssdeep_hash,
        compare as ssdeep_compare
    )
    from tlsh import (
        hash as tlsh_hash,
        diff as tlsh_diff
    )
except ImportError:
    pass

from idaclu import ida_shims


def manage_dir(dir_name, operation, is_abs):
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    dir_ops = {
        'mkdir': False,
        'rmdir': True,
        'chdir': True
    }
    if is_abs:
        func_dir.chdir('/')
    is_dir = func_dir.isdir(dir_name)
    if is_dir if dir_ops[operation] else not is_dir:
        if operation in dir_ops.keys():
            getattr(func_dir, operation)(dir_name)
        else:
            raise Exception('%s - invalid ida_dirtree operation' % (operation))
        return True
    return False

def create_dir(dir_name, is_abs=True):
    return manage_dir(dir_name, 'mkdir', is_abs)
    
def remove_dir(dir_name, is_abs=True):
    return manage_dir(dir_name, 'rmdir', is_abs)
    
def change_dir(dir_name, is_abs=True):
    return manage_dir(dir_name, 'chdir', is_abs)

# logic / prefixes '%' and '_' are the opposites:
# 1. '%' - has always single occurence, '_' - not;
# 2. '%' cannot appear at the very beginning of a function name, '_' - can;
# 3. '%' is purely internal prefix representation, '_' - human representation;
# 4. '%' are the prefixes added automatically, '_' - manually

def is_pfx_valid(pfx):
    a_facts = ['@', '$', '?', '-', '+']
    is_complex = any(a in pfx for a in a_facts)
    is_numeric = re.match('^[0-9]+', pfx)
    is_blanked = pfx == ''
    return not (is_complex or is_numeric or is_blanked)

def get_func_prefs(func_name, is_dummy=True):
    if ((func_name.startswith('?') and '@' in func_name) or
        func_name.startswith('_')):
        return []
    pfx_dummy = 'sub_'
    prefs = []
    pfx = ''

    idx = 0
    func_name = func_name.rstrip('_%:')
    while idx < len(func_name):
        char = func_name[idx]
        if char in ['%', ':', '_']:
            pfx_len = 1 
            while (idx+pfx_len) < len(func_name) and func_name[idx+pfx_len] in ['_', ':']:
                pfx_len += 1

            if idx != 0:
                # uncomment, if underscore tail in pfx is needed
                # pfx += func_name[idx:idx+pfx_len]
                if is_pfx_valid(pfx):
                    prefs.append(pfx)
                pfx = ''
                
            idx += pfx_len-1
        else:
            pfx += char

        idx += 1

    if not is_dummy and pfx_dummy in prefs:
        prefs.remove(pfx_dummy)
    return prefs

def get_cleaned_funcname(func_name, is_diff=False):
    bad_part = ''
    for char in func_name:
        if not char.isalpha():
            bad_part += char
        else:
            break

    if is_diff:
        return bad_part
    else:
        return func_name[len(bad_part):]

def refresh_ui():
    ida_shims.refresh_idaview_anyway()
    widget = ida_shims.get_current_widget()
    widget_vdui = ida_shims.get_widget_vdui(widget)
    if widget_vdui:
        widget_vdui.refresh_ctext()

def graph_down(ea, path=set()):
    path.add(ea)
    call_instructions = []
    for address in idautils.FuncItems(ea):
        if not ida_shims.decode_insn(address):
            continue
        if not idaapi.is_call_insn(address):
            continue
        call_instructions.append(address)

    for x in call_instructions:
        for r in idautils.XrefsFrom(x, idaapi.XREF_FAR):
            if not r.iscode:
                continue
            func = idaapi.get_func(r.to)
            if not func:
                continue
            if (func.flags & (idaapi.FUNC_THUNK | idaapi.FUNC_LIB)) != 0:
                continue
            if r.to not in path:
                graph_down(r.to, path)
    return path

def recursive_prefix(addr):
    func_addr = ida_shims.get_name_ea(idaapi.BADADDR, ida_shims.get_func_name(addr))
    if func_addr == idaapi.BADADDR:
        ida_shims.msg("ERROR: function is not defined at 0x%08X\n" % addr)
        return
    nodes_xref_down = graph_down(func_addr, path=set([]))
    return nodes_xref_down

def get_nodes_edges(func_addr):
    func = idaapi.get_func(func_addr)
    g = idaapi.FlowChart(func)

    node_count = len(list(g))
    edge_count = 0
    for x in g:
        succ_count = len(list(x.succs()))
        pred_count = len(list(x.preds()))
        edge_count += (succ_count + pred_count)
    return (node_count, edge_count)

def get_func_ea_by_ref(func_ref):
    if isinstance(func_ref, int):
        return func_ref
    elif isinstance(func_ref, str):
        return idc.get_name_ea_simple(func_ref)
    elif isinstance(func_ref, func_t):
        return func_ref.start_ea

def get_func_item_eas(func_ref):
    func_ea = get_func_ea_by_ref(func_ref)
    for item_ea in list(idautils.FuncItems(func_ea)):
        if idaapi.is_code(ida_shims.get_full_flags(func_ea)):
            yield item_ea

def get_func_item_eas_once(func_ref):
    item_eas = []
    for ea in get_func_item_eas(func_ref):
        item_eas.append(ea)
    return item_eas

def get_func_set_attrs(fn_start=['sub_'], is_fn_start=True, attrs=['indx','addr','name', 'size', 'attr']):
    for func_idx, func_addr in enumerate(idautils.Functions()):
        func_name = ida_shims.get_func_name(func_addr)
        func_attr = idc.get_func_attr(func_addr, idc.FUNCATTR_FLAGS)
        func_desc = idaapi.get_func(func_addr)
        func_size = ida_shims.calc_func_size(func_desc)
        if any(func_name.startswith(pat) == is_fn_start for pat in fn_start):  # all ??
            attr_set = ()
            if 'indx' in attrs:
                attr_set += (func_idx,)
            if 'addr' in attrs:
                attr_set += (func_addr,)
            if 'name' in attrs:
                attr_set += (func_name,)
            if 'size' in attrs:
                attr_set += (func_size,)
            if 'attr' in attrs:
                attr_set += (func_attr,)
            yield attr_set


def is_function_solved(func_ref):
    EXPL_CALL_ARTS = [
        'call sub_',
        'call _',
        'call ds:',
        'call nullsub_',
        'call loc_',
        'call off_',
        'call j_j__',
        'call ??',
        ';',
        'jmp',
        'jz short sub_'
    ]

    func_ea = get_func_ea_by_ref(func_ref)
    item_eas = get_func_item_eas_once(func_ea)
    for item_idx, item_ea in enumerate(item_eas):
        if ida_shims.ua_mnem(item_ea) == 'call':
            item_dasm = idc.generate_disasm_line(item_ea, idaapi.GENDSM_FORCE_CODE)
            item_dasm_norm = ' '.join(item_dasm.split())
            if not any(item_dasm_norm.startswith(art) for art in EXPL_CALL_ARTS) and ' ; ' not in item_dasm:
                return False
    else:
        return True


def is_function_leaf(func_ref):
    func_ea = get_func_ea_by_ref(func_ref)
    item_eas = [item_ea for item_ea in get_func_item_eas(func_ea)]
    for item_ea in item_eas:
        if ida_shims.ua_mnem(item_ea) == 'call':
            return False
    else:
        if ida_shims.ua_mnem(item_eas[-1]) == 'jmp':
            return False
        else:
            return True  # until some "calling activity" is discovered inside,
                         # each function is considered as a "leaf"-function

def get_dir_metrics(root_dir):
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    ite = ida_dirtree.dirtree_iterator_t()

    s_folders = [root_dir]
    u_folders = collections.defaultdict(int)

    while len(s_folders):
        curr_path = s_folders.pop()
        func_dir.chdir(curr_path)
        status = func_dir.findfirst(ite, "*")

        while status:
            entry_name = func_dir.get_entry_name(func_dir.resolve_cursor(ite.cursor))
            cursor_abspath = func_dir.get_abspath(ite.cursor)
            if func_dir.isdir(cursor_abspath):
                current_dir_new = '{}/{}'.format('' if curr_path == '/' else curr_path, entry_name)
                s_folders.append(current_dir_new)
            elif func_dir.isfile(cursor_abspath):
                func_addr = idaapi.get_name_ea(0, entry_name)
                u_folders[curr_path] += 1   
            status = func_dir.findnext(ite)

    return list(u_folders.items())

def get_func_dirs(root_dir):
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    ite = ida_dirtree.dirtree_iterator_t()

    s_folders = [root_dir]
    u_folders = [root_dir]

    while len(s_folders):
        curr_path = s_folders.pop()
        func_dir.chdir(curr_path)
        status = func_dir.findfirst(ite, "*")

        while status:
            entry_name = func_dir.get_entry_name(func_dir.resolve_cursor(ite.cursor))
            if func_dir.isdir(func_dir.get_abspath(ite.cursor)):
                current_dir_new = '{}/{}'.format('' if curr_path == '/' else curr_path, entry_name)
                s_folders.append(current_dir_new)
                if not current_dir_new in u_folders:
                    u_folders.append(current_dir_new)
            status = func_dir.findnext(ite)

    return u_folders

def get_dir_funcs(folders, is_root=True):
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    ite = ida_dirtree.dirtree_iterator_t()
    idx = 0

    funcs = {}
    while idx < len(folders):
        curr_path = folders[idx]
        func_dir.chdir(curr_path)
        status = func_dir.findfirst(ite, "*")

        while status:
            entry_name = func_dir.get_entry_name(func_dir.resolve_cursor(ite.cursor))
            func_addr = ida_shims.get_name_ea(0, entry_name)
            if func_dir.isfile(func_dir.get_abspath(ite.cursor)):
                if is_root == False and curr_path == '/':
                    # if only the functions with non-standard dir are needed
                    pass
                else:
                    funcs[func_addr] = curr_path
            status = func_dir.findnext(ite)
        idx += 1

    return funcs

def get_func_name(func_ref):
    func_name = None
    if isinstance(func_ref, str):
        func_name = func_ref
    elif isinstance(func_ref, int):
        func_name = ida_shims.get_func_name(func_ref)
    else:
        raise ValueError("Invalid func reference")
    return func_name

def get_folder_norm(folder):
    return '' if folder == '/' else folder

def set_func_folder(func_ref, folder_src, folder_dst):
    func_name = get_func_name(func_ref)
    func_src = '{}/{}'.format(get_folder_norm(folder_src), func_name)
    func_dst = '{}/{}'.format(get_folder_norm(folder_dst), func_name)

    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    func_dir.chdir('/')
    func_dir.rename(func_src, func_dst)

def is_in_interval(addr, func_ivals, is_strict):
    if is_strict:
        return any(beg < addr < end for beg, end in func_ivals)
    else:
        return any(beg <= addr <= end for beg, end in func_ivals)

def get_func_ivals(func_addr):
    return [(func_beg, func_end) for func_beg, func_end in ida_shims.get_chunk_eas(func_addr)]

def get_chunk_count(func_addr):
    num_chunks = len(get_func_ivals(func_addr))
    return num_chunks

def is_addr_func(addr, func_addr, is_chunks, is_strict):
    func_ivals = None
    if is_chunks:
        func_ivals = get_func_ivals(func_addr)
    else:
        func_beg = func_addr
        func_end = idc.get_func_attr(func_addr, idc.FUNCATTR_END)
        func_ivals = [(func_beg, func_end)]

    return is_in_interval(addr, func_ivals, is_strict)

def is_func_wrapper(func_addr, is_precise=True):
    """
    Wrapper functions are typically short.
    x86_64 instructions can be up to 15 bytes in length, at average - 4/5;
    The defined frame is 64b, then a very rough approximation is as follows:
        15 bytes/instr ->  4 instr/func ->  1- 2 statements (min)
         5 bytes/instr -> 12 instr/func ->  4- 6 statements
         4 bytes/instr -> 16 instr/func ->  5- 8 statements
         2 bytes/instr -> 32 instr/func -> 10-11 statements (max)
    It is not sufficient to look up solely for function size,
    important to have instruction count boundary as well,
    because of the function chunks e.g. func_size=14 bytes, inst_count=99;
    Small function with many instructions is either "super slim" function,
    or it has unaccounted chunks.
    """

    flags = ida_shims.get_func_flags(func_addr)
    func_items = list(idautils.FuncItems(func_addr))

    api_pairs = [
        ('EnterCriticalSection', 'LeaveCriticalSection'),
        ('__SEH_prolog', '__SEH_epilog'),
        ('__lock', '__unlock'),
        ('__lockexit', '__unlockexit'),
        ('__lock_fhandle', '__unlock_fhandle'),
        ('__lock_file', '__unlock_file'),
        ('__lock_file2', '__unlock_file2'),
        ('_malloc', '_free'),
        ('_calloc', '_free'),
        ('_realloc', '_free'),
        ('___initstdio', '___endstdio'),
        ('__Init_thread_header', '__Init_thread_footer'),
        ('_fopen', '_fclose'),
        ('CreateMutexA', 'ReleaseMutex'),
        ('CreateMutexW', 'ReleaseMutex'),
        ('CreateSemaphoreA', 'ReleaseSemaphore'),
        ('CreateSemaphoreW', 'ReleaseSemaphore'),
        ('CreateThread', 'ExitThread'),
        ('AcquireSRWLockExclusive ', 'ReleaseSRWLockExclusive'),
        ('InitializeSRWLock  ', 'DeleteSRWLock'),
        ('CreateFileA', 'CloseHandle'),
        ('CreateFileW', 'CloseHandle'),
        ('VirtualProtect', 'VirtualFree'),
        ('HeapAlloc', 'HeapFree'),
        ('HeapReAlloc', 'HeapFree'),
        ('HeapCreate', 'HeapDestroy'),
        ('RegOpenKeyA', 'RegCloseKey'),
        ('RegOpenKeyW', 'RegCloseKey'),
        ('TlsAlloc', 'TlsFree'),
        ('GlobalLock', 'GlobalUnlock'),
        ('BeginPaint', 'EndPaint'),
        ('OpenProcess', 'ExitProcess'),
        ('CreateWindowExA', 'DestroyWindow'),
        ('CreateWindowExW', 'DestroyWindow'),
        ('___sbh_alloc_block', '___sbh_free_block')
    ]
    api_pair_beg = [p[0] for p in api_pairs]
    api_pair_end = [p[1] for p in api_pairs]

    func_beg = func_addr
    func_end = ida_shims.get_func_attr(func_addr, idc.FUNCATTR_END)

    call_num = 0
    pair_unm = []
    call_reg = set()
    func_nam = ida_shims.get_name(func_addr)
    func_mod = set()
    func_res = False
    # exclude recursive calls
    call_reg.add(func_nam)
    for inst_addr in idautils.FuncItems(func_addr):
        if is_precise:
            mnem = ida_shims.print_insn_mnem(inst_addr)
            oprd_val = ida_shims.get_operand_value(inst_addr, 0)
            oprd_typ = ida_shims.get_operand_type(inst_addr, 0)
            if (mnem == 'jmp' and 
                not is_addr_func(oprd_val, func_addr, is_precise, True)):
                call_nam = ida_shims.get_name(oprd_val)
                # exclude jump tables;
                # consider the case when there is more than one jmp/call inst.
                # pointing to the same function: call x, call x, jmp x
                if not call_nam.startswith('loc_') and not call_nam in call_reg:
                    call_num += 1
                    call_reg.add(call_nam)

            if mnem == 'call':
                if oprd_typ in [idc.o_mem, idc.o_far, idc.o_near]:
                    call_dst = list(idautils.CodeRefsFrom(inst_addr, 0))
                    if len(call_dst):
                        call_nam = ida_shims.get_name(call_dst[0])
                        if call_nam in api_pair_beg:
                            pair_unm.append(api_pair_beg.index(call_nam))
                        elif call_nam in api_pair_end:
                            elem_idx = api_pair_end.index(call_nam)
                            if elem_idx in pair_unm:
                                # there are numerous pair APIs of the form:
                                # alloc/free, open/close, create/destroy;
                                # consider the impact of a wrapping pair as - 0
                                pair_unm.remove(elem_idx)
                            else:
                                pair_unm.append(elem_idx)
                        else:
                            if not call_nam in call_reg and not call_nam in ['j__free']:
                                call_num += 1
                                call_reg.add(call_nam)
                elif is_precise and (oprd_typ in [idc.o_displ]):
                    dasm_line = ida_shims.generate_disasm_line(inst_addr, idaapi.GENDSM_FORCE_CODE)
                    call_vft = ' '.join(' '.join(dasm_line.split()).split()[1:])
                    if not call_vft in call_reg:
                        func_mod.add("ptr")
                        call_num += 1
                        call_reg.add(call_vft)

    if (call_num + len(pair_unm)) == 1:
        func_res = True
        if ((func_end - func_addr) > 0 and (func_end - func_addr) < 64) and len(func_items) <= 32:
            func_mod.add("small")
        else:
            # an attempt to collect wrapper functions that
            # otherwise will be missed due to too strict size constraint;
            # they are not that simple, have some additional logic
            # that probably should be considered separately
            func_mod.add("large")

    return (func_res, list(func_mod))

def is_func_thunk(func_addr):
    func_flags = ida_shims.get_func_flags(func_addr)
    return func_flags & idaapi.FUNC_THUNK

def get_code_refs_to(addr):
    return set([cref for cref in idautils.CodeRefsTo(addr, 0)])

def get_data_refs_to(addr):
    return set([dref for dref in idautils.DataRefsTo(addr)])

def get_refs_to(addr):
    return iter(get_code_refs_to(addr).union(get_data_refs_to(addr)))

def is_arch64():
    return bool(idaapi.getseg(ida_shims.get_first_seg()).bitness == 2)

def get_ptr_type():
    return [FF_DWORD, FF_QWORD][is_arch64()]

def get_ref_off():
    return [REF_OFF32, REF_OFF64][is_arch64()]

def get_ptr_size():
    return [4, 8][is_arch64()]

def get_ptr(addr):
    return [idaapi.get_32bit, idaapi.get_64bit][is_arch64()](addr)

def is_GCC_auto():
    if get_compiler_name() == 'GNU C++':
        return True
    return False

def is_GCC_manual():
    gcc_rtti_artifacts = [
        "St9type_info",
        "N10__cxxabiv117__class_type_infoE",
        "N10__cxxabiv120__si_class_type_infoE",
        "N10__cxxabiv121__vmi_class_type_infoE"
    ]

    flag = idaapi.SEARCH_CASE|idaapi.SEARCH_DOWN
    for art in gcc_rtti_artifacts:
        gcc_info = ida_shims.find_text(0x0, 0, 0, art, flag)
        if gcc_info != idaapi.BADADDR:
            return True
    return False

def is_vtable(addr):
    if addr and has_xref(addr):
        func_ea = get_ptr(addr)
        if func_ea and idaapi.getseg(func_ea):
            if ida_shims.get_segm_attr(func_ea, idc.SEGATTR_TYPE) == idc.SEG_CODE:
                func_desc = idaapi.get_func(func_ea)
                if func_desc and func_ea == ida_shims.start_ea(func_desc):
                    return True
    return False

def has_xref(addr):
    return ida_shims.has_xref(ida_shims.get_full_flags(addr))

def get_compiler_name():
    inf_cc_id = ida_shims.inf_get_cc_id()
    return idaapi.get_compiler_name(inf_cc_id)

def get_func_params(func_addr):
    params = []
    tif = idaapi.tinfo_t()
    if idaapi.get_tinfo(tif, func_addr):
        func_type_data = idaapi.func_type_data_t()
        if tif.get_func_details(func_type_data):
            for i, arg in enumerate(func_type_data):
                arg_name = arg.name if arg.name else 'a{}'.format(i+1)
                params.append({
                    "name": arg_name,
                    "type": arg.type.dstr()
                })
    return params

def check_type(type_name, type_list):
    for t in type_list:
        if type_name == t or f' {t}' in type_name or f'{t} ' in type_name:
            return True
    return False

def is_std_type(type_name):
    TYPES = [
        'void',
        'bool',
        'int',
        'short',
        'long',
        'float',
        'double',
        'char',
        'char16_t',
        'char32_t',
        'wchar_t',
        '__int8',
        '__int16',
        '__int32',
        '__int64',
        '__int128',
        '__m64',
        '__m128',
        '__m128d',
        '__m128i',
        'size_t',
        'FILE'
    ]
    return check_type(type_name, TYPES)

def is_win_type(type_name):
    TYPES = [
        'APIENTRY',
        'ATOM',
        'BOOL',
        'BOOLEAN',
        'BYTE',
        'CALLBACK',
        'CCHAR',
        'CHAR',
        'COLORREF',
        'CONST',
        'DWORD',
        'DWORDLONG',
        'DWORD_PTR',
        'DWORD32',
        'DWORD64',
        'FLOAT',
        'HACCEL',
        'HALF_PTR',
        'HANDLE',
        'HBITMAP',
        'HBRUSH',
        'HCOLORSPACE',
        'HCONV',
        'HCONVLIST',
        'HCURSOR',
        'HDC',
        'HDDEDATA',
        'HDESK',
        'HDROP',
        'HDWP',
        'HENHMETAFILE',
        'HFILE',
        'HFONT',
        'HGDIOBJ',
        'HGLOBAL',
        'HHOOK',
        'HICON',
        'HINSTANCE',
        'HKEY',
        'HKL',
        'HLOCAL',
        'HMENU',
        'HMETAFILE',
        'HMODULE',
        'HMONITOR',
        'HPALETTE',
        'HPEN',
        'HRESULT',
        'HRGN',
        'HRSRC',
        'HSZ',
        'HWINSTA',
        'HWND',
        'INT',
        'INT_PTR',
        'INT8',
        'INT16',
        'INT32',
        'INT64',
        'LANGID',
        'LCID',
        'LCTYPE',
        'LGRPID',
        'LONG',
        'LONGLONG',
        'LONG_PTR',
        'LONG32',
        'LONG64',
        'LPARAM',
        'LPBOOL',
        'LPBYTE',
        'LPCOLORREF',
        'LPCSTR',
        'LPCTSTR',
        'LPCVOID',
        'LPCWSTR',
        'LPDWORD',
        'LPHANDLE',
        'LPINT',
        'LPLONG',
        'LPSTR',
        'LPTSTR',
        'LPVOID',
        'LPWORD',
        'LPWSTR',
        'LRESULT',
        'PBOOL',
        'PBOOLEAN',
        'PBYTE',
        'PCHAR',
        'PCSTR',
        'PCTSTR',
        'PCWSTR',
        'PDWORD',
        'PDWORDLONG',
        'PDWORD_PTR',
        'PDWORD32',
        'PDWORD64',
        'PFLOAT',
        'PHALF_PTR',
        'PHANDLE',
        'PHKEY',
        'PINT',
        'PINT_PTR',
        'PINT8',
        'PINT16',
        'PINT32',
        'PINT64',
        'PLCID',
        'PLONG',
        'PLONGLONG',
        'PLONG_PTR',
        'PLONG32',
        'PLONG64',
        'POINTER_32',
        'POINTER_64',
        'POINTER_SIGNED',
        'POINTER_UNSIGNED',
        'PSHORT',
        'PSIZE_T',
        'PSSIZE_T',
        'PSTR',
        'PTBYTE',
        'PTCHAR',
        'PTSTR',
        'PUCHAR',
        'PUHALF_PTR',
        'PUINT',
        'PUINT_PTR',
        'PUINT8',
        'PUINT16',
        'PUINT32',
        'PUINT64',
        'PULONG',
        'PULONGLONG',
        'PULONG_PTR',
        'PULONG32',
        'PULONG64',
        'PUSHORT',
        'PVOID',
        'PWCHAR',
        'PWORD',
        'PWSTR',
        'QWORD',
        'SC_HANDLE',
        'SC_LOCK',
        'SERVICE_STATUS_HANDLE',
        'SHORT',
        'SIZE_T',
        'SSIZE_T',
        'TBYTE',
        'TCHAR',
        'UCHAR',
        'UHALF_PTR',
        'UINT',
        'UINT_PTR',
        'UINT8',
        'UINT16',
        'UINT32',
        'UINT64',
        'ULONG',
        'ULONGLONG',
        'ULONG_PTR',
        'ULONG32',
        'ULONG64',
        'UNICODE_STRING',
        'USHORT',
        'USN',
        'VOID',
        'WCHAR',
        'WINAPI',
        'WORD',
        'WPARAM'
    ]
    return check_type(type_name, TYPES)

def is_directx_type(type_name):
    TYPES = [
        'D3DBLEND',
        'D3DBRANCH',
        'D3DCMPFUNC',
        'D3DCOLOR',
        'D3DCOLORMODEL',
        'D3DCOLORVALUE',
        'D3DCULL',
        'D3DDEVICEDESC',
        'D3DEXECUTEBUFFERDESC',
        'D3DEXECUTEDATA',
        'D3DFILLMODE',
        'D3DFINDDEVICERESULT',
        'D3DFINDDEVICESEARCH',
        'D3DFIXED',
        'D3DFOGMODE',
        'D3DHVERTEX',
        'D3DINSTRUCTION',
        'D3DLIGHT',
        'D3DLIGHTDATA',
        'D3DLIGHTINGCAPS',
        'D3DLIGHTINGELEMENT',
        'D3DLIGHTSTATETYPE',
        'D3DLIGHTTYPE',
        'D3DLINE',
        'D3DLINEPATTERN',
        'D3DLVERTEX',
        'D3DMATERIAL',
        'D3DMATERIALHANDLE',
        'D3DMATRIX',
        'D3DMATRIXHANDLE',
        'D3DMATRIXLOAD',
        'D3DMATRIXMULTIPLY',
        'D3DOPCODE',
        'D3DPICKRECORD',
        'D3DPOINT',
        'D3DPRIMCAPS',
        'D3DPROCESSVERTICES',
        'D3DRECT',
        'D3DRENDERSTATETYPE',
        'D3DRMANIMATIONOPTIONS',
        'D3DRMBOX',
        'D3DRMCOLORMODEL',
        'D3DRMCOLORSOURCE',
        'D3DRMCOMBINETYPE',
        'D3DRMDEVICEPALETTECALLBACK',
        'D3DRMFILLMODE',
        'D3DRMFOGMODE',
        'D3DRMFRAMECONSTRAINT',
        'D3DRMFRAMEMOVECALLBACK',
        'D3DRMGROUPINDEX',
        'D3DRMIMAGE',
        'D3DRMLIGHTMODE',
        'D3DRMLIGHTTYPE',
        'D3DRMLOADCALLBACK',
        'D3DRMLOADMEMORY',
        'D3DRMLOADOPTIONS',
        'D3DRMLOADRESOURCE',
        'D3DRMLOADTEXTURECALLBACK',
        'D3DRMMAPPING',
        'D3DRMMAPPINGFLAG',
        'D3DRMMATERIALMODE',
        'D3DRMMATRIX4D',
        'D3DRMOBJECTCALLBACK',
        'D3DRMPALETTEENTRY',
        'D3DRMPALETTEFLAGS',
        'D3DRMPICKDESC',
        'D3DRMPROJECTIONTYPE',
        'D3DRMQUATERNION',
        'D3DRMRENDERQUALITY',
        'D3DRMSAVEOPTIONS',
        'D3DRMSHADEMODE',
        'D3DRMSORTMODE',
        'D3DRMTEXTUREQUALITY',
        'D3DRMUPDATECALLBACK',
        'D3DRMUSERVISUALCALLBACK',
        'D3DRMUSERVISUALREASON',
        'D3DRMVECTOR4D',
        'D3DRMVERTEX',
        'D3DRMWRAPCALLBACK',
        'D3DRMWRAPTYPE',
        'D3DRMXOFFORMAT',
        'D3DRMZBUFFERMODE',
        'D3DSHADEMODE',
        'D3DSPAN',
        'D3DSTATE',
        'D3DSTATS',
        'D3DSTATUS',
        'D3DTEXTUREADDRESS',
        'D3DTEXTUREBLEND',
        'D3DTEXTUREFILTER',
        'D3DTEXTUREHANDLE',
        'D3DTEXTURELOAD',
        'D3DTLVERTEX',
        'D3DTRANSFORMCAPS',
        'D3DTRANSFORMDATA',
        'D3DTRANSFORMSTATETYPE',
        'D3DTRIANGLE',
        'D3DVALUE',
        'D3DVECTOR',
        'D3DVERTEX',
        'D3DVIEWPORT',
        'DDBLTBATCH',
        'DDBLTFX',
        'DDCAPS',
        'DDCOLORKEY',
        'DDOVERLAYFX',
        'DDPIXELFORMAT',
        'DDSCAPS',
        'DDSURFACEDESC',
        'DIDATAFORMAT',
        'DIDEVCAPS',
        'DIDEVICEINSTANCE',
        'DIDEVICEINSTANCE',
        'DIDEVICEINSTANCEA',
        'DIDEVICEINSTANCEW',
        'DIDEVICEOBJECTDATA',
        'DIDEVICEOBJECTINSTANCE',
        'DIDEVICEOBJECTINSTANCE',
        'DIDEVICEOBJECTINSTANCEA',
        'DIDEVICEOBJECTINSTANCEW',
        'DIMOUSESTATE',
        'DIOBJECTDATAFORMAT',
        'DIPROPDWORD',
        'DIPROPHEADER',
        'DIPROPRANGE',
        'DIRECTXREGISTERAPP',
        'DIRECTXREGISTERAPP',
        'DIRECTXREGISTERAPPA',
        'DIRECTXREGISTERAPPW',
        'DPADDRESS',
        'DPCAPS',
        'DPCOMPORTADDRESS',
        'DPID',
        'DPLAPPINFO',
        'DPLCONNECTION',
        'DPLMSG_GENERIC',
        'DPMSG_ADDGROUP',
        'DPMSG_ADDPLAYER',
        'DPMSG_ADDPLAYERTOGROUP',
        'DPMSG_CREATEPLAYERORGROUP',
        'DPMSG_DELETEPLAYER',
        'DPMSG_DELETEPLAYERFROMGROUP',
        'DPMSG_DESTROYPLAYERORGROUP',
        'DPMSG_GENERIC',
        'DPMSG_GROUPADD',
        'DPMSG_GROUPDELETE',
        'DPMSG_HOST',
        'DPMSG_SESSIONLOST',
        'DPMSG_SETPLAYERORGROUPDATA',
        'DPMSG_SETPLAYERORGROUPNAME',
        'DPNAME',
        'DPSESSIONDESC',
        'DPSESSIONDESC2',
        'DS3DBUFFER',
        'DS3DLISTENER',
        'DSBCAPS',
        'DSBUFFERDESC',
        'DSCAPS',
        'HFASTFILE',
        'HRESULT',
        'IDirectPlay2A',
        'IDirectPlayLobbyA',
        'LPCDIDATAFORMAT',
        'LPCDIDEVICEINSTANCE',
        'LPCDIDEVICEINSTANCEA',
        'LPCDIDEVICEINSTANCEW',
        'LPCDIDEVICEOBJECTINSTANCE',
        'LPCDIDEVICEOBJECTINSTANCEA',
        'LPCDIDEVICEOBJECTINSTANCEW',
        'LPCDIOBJECTDATAFORMAT',
        'LPCDIPROPDWORD',
        'LPCDIPROPHEADER',
        'LPCDIPROPRANGE',
        'LPCDPLAPPINFO',
        'LPCDPLCONNECTION',
        'LPCDPNAME',
        'LPCDPSESSIONDESC2',
        'LPCLIPPERCALLBACK',
        'LPD3DBRANCH',
        'LPD3DCOLOR',
        'LPD3DDEVICEDESC',
        'LPD3DENUMDEVICESCALLBACK',
        'LPD3DENUMTEXTUREFORMATSCALLBACK',
        'LPD3DEXECUTEBUFFERDESC',
        'LPD3DEXECUTEDATA',
        'LPD3DFINDDEVICERESULT',
        'LPD3DFINDDEVICESEARCH',
        'LPD3DHVERTEX',
        'LPD3DINSTRUCTION',
        'LPD3DLIGHT',
        'LPD3DLIGHTDATA',
        'LPD3DLIGHTINGCAPS',
        'LPD3DLIGHTINGELEMENT',
        'LPD3DLINE',
        'LPD3DLVERTEX',
        'LPD3DMATERIAL',
        'LPD3DMATERIALHANDLE',
        'LPD3DMATRIX',
        'LPD3DMATRIXHANDLE',
        'LPD3DMATRIXLOAD',
        'LPD3DMATRIXMULTIPLY',
        'LPD3DPICKRECORD',
        'LPD3DPOINT',
        'LPD3DPRIMCAPS',
        'LPD3DPROCESSVERTICES',
        'LPD3DRECT',
        'LPD3DRMBOX',
        'LPD3DRMCOLORMODEL',
        'LPD3DRMCOLORSOURCE',
        'LPD3DRMCOMBINETYPE',
        'LPD3DRMFILLMODE',
        'LPD3DRMFOGMODE',
        'LPD3DRMFRAMECONSTRAINT',
        'LPD3DRMIMAGE',
        'LPD3DRMLIGHTMODE',
        'LPD3DRMLIGHTTYPE',
        'LPD3DRMLOADMEMORY',
        'LPD3DRMLOADRESOURCE',
        'LPD3DRMMAPPING',
        'LPD3DRMMATERIALMODE',
        'LPD3DRMPALETTEENTRY',
        'LPD3DRMPALETTEFLAGS',
        'LPD3DRMPICKDESC',
        'LPD3DRMPROJECTIONTYPE',
        'LPD3DRMQUATERNION',
        'LPD3DRMRENDERQUALITY',
        'LPD3DRMSHADEMODE',
        'LPD3DRMSORTMODE',
        'LPD3DRMTEXTUREQUALITY',
        'LPD3DRMUSERVISUALREASON',
        'LPD3DRMVECTOR4D',
        'LPD3DRMVERTEX',
        'LPD3DRMWRAPTYPE',
        'LPD3DRMXOFFORMAT',
        'LPD3DRMZBUFFERMODE',
        'LPD3DSPAN',
        'LPD3DSTATE',
        'LPD3DSTATS',
        'LPD3DSTATUS',
        'LPD3DTEXTUREHANDLE',
        'LPD3DTEXTURELOAD',
        'LPD3DTLVERTEX',
        'LPD3DTRANSFORMCAPS',
        'LPD3DTRANSFORMDATA',
        'LPD3DTRIANGLE',
        'LPD3DVALIDATECALLBACK',
        'LPD3DVALUE',
        'LPD3DVECTOR',
        'LPD3DVERTEX',
        'LPD3DVIEWPORT',
        'LPDDBLTBATCH',
        'LPDDBLTFX',
        'LPDDCAPS',
        'LPDDCOLORKEY',
        'LPDDENUMCALLBACK',
        'LPDDENUMCALLBACK',
        'LPDDENUMCALLBACKA',
        'LPDDENUMCALLBACKW',
        'LPDDENUMMODESCALLBACK',
        'LPDDENUMSURFACESCALLBACK',
        'LPDDFXROP',
        'LPDDOVERLAYFX',
        'LPDDPIXELFORMAT',
        'LPDDSCAPS',
        'LPDDSURFACEDESC',
        'LPDIDATAFORMAT',
        'LPDIDEVCAPS',
        'LPDIDEVICEINSTANCE',
        'LPDIDEVICEINSTANCE',
        'LPDIDEVICEINSTANCEA',
        'LPDIDEVICEINSTANCEW',
        'LPDIDEVICEOBJECTDATA',
        'LPDIDEVICEOBJECTINSTANCE',
        'LPDIDEVICEOBJECTINSTANCE',
        'LPDIDEVICEOBJECTINSTANCEA',
        'LPDIDEVICEOBJECTINSTANCEW',
        'LPDIENUMDEVICEOBJECTSCALLBACKA',
        'LPDIENUMDEVICEOBJECTSCALLBACKW',
        'LPDIENUMDEVICESCALLBACKA',
        'LPDIENUMDEVICESCALLBACKW',
        'LPDIMOUSESTATE',
        'LPDIOBJECTDATAFORMAT',
        'LPDIPROPDWORD',
        'LPDIPROPHEADER',
        'LPDIPROPRANGE',
        'LPDIRECT3D',
        'LPDIRECT3D',
        'LPDIRECT3DDEVICE',
        'LPDIRECT3DDEVICE',
        'LPDIRECT3DEXECUTEBUFFER',
        'LPDIRECT3DEXECUTEBUFFER',
        'LPDIRECT3DLIGHT',
        'LPDIRECT3DLIGHT',
        'LPDIRECT3DMATERIAL',
        'LPDIRECT3DMATERIAL',
        'LPDIRECT3DTEXTURE',
        'LPDIRECT3DTEXTURE',
        'LPDIRECT3DVIEWPORT',
        'LPDIRECT3DVIEWPORT',
        'LPDIRECTDRAW',
        'LPDIRECTDRAW2',
        'LPDIRECTDRAWCLIPPER',
        'LPDIRECTDRAWPALETTE',
        'LPDIRECTDRAWSURFACE',
        'LPDIRECTDRAWSURFACE2',
        'LPDIRECTINPUT',
        'LPDIRECTINPUTA',
        'LPDIRECTINPUTDEVICE',
        'LPDIRECTINPUTDEVICEA',
        'LPDIRECTINPUTDEVICEW',
        'LPDIRECTINPUTW',
        'LPDIRECTPLAY',
        'LPDIRECTPLAY',
        'LPDIRECTPLAY2',
        'LPDIRECTPLAY2A',
        'LPDIRECTPLAYLOBBY',
        'LPDIRECTPLAYLOBBYA',
        'LPDIRECTSOUND',
        'LPDIRECTSOUND3DBUFFER',
        'LPDIRECTSOUND3DLISTENER',
        'LPDIRECTSOUNDBUFFER',
        'LPDIRECTXDEVICEDRIVERSETUP',
        'LPDIRECTXDEVICEDRIVERSETUP',
        'LPDIRECTXREGISTERAPP',
        'LPDIRECTXREGISTERAPP',
        'LPDIRECTXREGISTERAPPA',
        'LPDIRECTXREGISTERAPPLICATION',
        'LPDIRECTXREGISTERAPPLICATION',
        'LPDIRECTXREGISTERAPPW',
        'LPDIRECTXSETUP',
        'LPDIRECTXSETUP',
        'LPDIRECTXSETUPISJAPAN',
        'LPDIRECTXSETUPISJAPANNEC',
        'LPDPADDRESS',
        'LPDPCAPS',
        'LPDPCOMPORTADDRESS',
        'LPDPENUMADDRESSCALLBACK',
        'LPDPENUMDPCALLBACK',
        'LPDPENUMDPCALLBACKA',
        'LPDPENUMPLAYERSCALLBACK',
        'LPDPENUMPLAYERSCALLBACK2',
        'LPDPENUMSESSIONSCALLBACK',
        'LPDPENUMSESSIONSCALLBACK2',
        'LPDPID',
        'LPDPLAPPINFO',
        'LPDPLCONNECTION',
        'LPDPLENUMADDRESSTYPESCALLBACK',
        'LPDPLENUMLOCALAPPLICATIONSCALLBACK',
        'LPDPLMSG_GENERIC',
        'LPDPMSG_ADDPLAYERTOGROUP',
        'LPDPMSG_CREATEPLAYERORGROUP',
        'LPDPMSG_DELETEPLAYERFROMGROUP',
        'LPDPMSG_DESTROYPLAYERORGROUP',
        'LPDPMSG_GENERIC',
        'LPDPMSG_HOST',
        'LPDPMSG_SESSIONLOST',
        'LPDPMSG_SETPLAYERORGROUPDATA',
        'LPDPMSG_SETPLAYERORGROUPNAME',
        'LPDPNAME',
        'LPDPSESSIONDESC',
        'LPDPSESSIONDESC2',
        'LPDS3DBUFFER',
        'LPDS3DLISTENER',
        'LPDSBCAPS',
        'LPDSBUFFERDESC',
        'LPDSCAPS',
        'LPDSENUMCALLBACKA',
        'LPDSENUMCALLBACKW',
        'LPLPDIRECTSOUNDBUFFER',
        'LPLPVOID',
        'LPSURFACESTREAMINGCALLBACK',
        'PDIRECTXREGISTERAPP',
        'PDIRECTXREGISTERAPP',
        'PDIRECTXREGISTERAPPA',
        'PDIRECTXREGISTERAPPW',
        '_D3DBRANCH',
        '_D3DCOLORVALUE',
        '_D3DDeviceDesc',
        '_D3DExecuteBufferDesc',
        '_D3DEXECUTEDATA',
        '_D3DFINDDEVICERESULT',
        '_D3DFINDDEVICESEARCH',
        '_D3DHVERTEX',
        '_D3DINSTRUCTION',
        '_D3DLIGHT',
        '_D3DLIGHTDATA',
        '_D3DLIGHTINGCAPS',
        '_D3DLIGHTINGELEMENT',
        '_D3DLINE',
        '_D3DLINEPATTERN',
        '_D3DLVERTEX',
        '_D3DMATERIAL',
        '_D3DMATRIX',
        '_D3DMATRIXLOAD',
        '_D3DMATRIXMULTIPLY',
        '_D3DPICKRECORD',
        '_D3DPOINT',
        '_D3DPrimCaps',
        '_D3DPROCESSVERTICES',
        '_D3DRECT',
        '_D3DRMBOX',
        '_D3DRMIMAGE',
        '_D3DRMLOADMEMORY',
        '_D3DRMLOADRESOURCE',
        '_D3DRMPALETTEENTRY',
        '_D3DRMPICKDESC',
        '_D3DRMQUATERNION',
        '_D3DRMVECTOR4D',
        '_D3DRMVERTEX',
        '_D3DSPAN',
        '_D3DSTATE',
        '_D3DSTATS',
        '_D3DSTATUS',
        '_D3DTEXTURELOAD',
        '_D3DTLVERTEX',
        '_D3DTRANSFORMCAPS',
        '_D3DTRANSFORMDATA',
        '_D3DTRIANGLE',
        '_D3DVECTOR',
        '_D3DVERTEX',
        '_D3DVIEWPORT',
        '_DDBLTBATCH',
        '_DDBLTFX',
        '_DDCAPS',
        '_DDCOLORKEY',
        '_DDOVERLAYFX',
        '_DDPIXELFORMAT',
        '_DDSCAPS',
        '_DDSURFACEDESC',
        '_DIDATAFORMAT',
        '_DIDEVCAPS',
        '_DIMOUSESTATE',
        '_DIOBJECTDATAFORMAT',
        '_DIRECTXREGISTERAPPA',
        '_DIRECTXREGISTERAPPW',
        '_DPADDRESS',
        '_DPCOMPORTADDRESS',
        '_DS3DBUFFER',
        '_DS3DLISTENER',
        '_DSBCAPS',
        '_DSBUFFERDESC',
        '_DSCAPS',
        'DIDEVICEINSTANCEA',
        'DIDEVICEINSTANCEW',
        'DIDEVICEOBJECTDATA',
        'DIDEVICEOBJECTINSTANCEA',
        'DIDEVICEOBJECTINSTANCEW',
        'DIPROPDWORD',
        'DIPROPHEADER',
        'DIPROPRANGE',
        'DPLAPPINFO',
        'DPLCONNECTION',
        'DPLMSG_GENERIC'
    ]
    return check_type(type_name, TYPES)

def is_unk_type(type_name):
    # Example: `const #1641 *`
    return '#' in type_name

def get_dt_type(type_name):
    if is_std_type(type_name):
        return "std"
    elif is_win_type(type_name):
        return "win"
    elif is_directx_type(type_name):
        return "ddx"
    elif is_unk_type(type_name):
        return "unk"
    else:
        return "usr"
        
def is_fn_typ_type(type_name):
    TYPES = [
        'BYTE1',
        'BYTE2',
        'BYTE3',
        'BYTE4',
        'BYTE5',
        'BYTE6',
        'BYTE7',
        'BYTE8',
        'BYTE9',
        'BYTE10',
        'BYTE11',
        'BYTE12',
        'BYTE13',
        'BYTE14',
        'BYTE15',
        'WORD1',
        'WORD2',
        'WORD3',
        'WORD4',
        'WORD5',
        'WORD6',
        'WORD7',
        'LOBYTE',
        'LOWORD',
        'LODWORD',
        'HIBYTE',
        'HIWORD',
        'HIDWORD',
        'SBYTE1',
        'SBYTE2',
        'SBYTE3',
        'SBYTE4',
        'SBYTE5',
        'SBYTE6',
        'SBYTE7',
        'SBYTE8',
        'SBYTE9',
        'SBYTE10',
        'SBYTE11',
        'SBYTE12',
        'SBYTE13',
        'SBYTE14',
        'SBYTE15',
        'SWORD1',
        'SWORD2',
        'SWORD3',
        'SWORD4',
        'SWORD5',
        'SWORD6',
        'SWORD7',
        'SLOBYTE',
        'SLOWORD',
        'SLODWORD',
        'SHIBYTE',
        'SHIWORD',
        'SHIDWORD',
        'COERCE_FLOAT',
        'COERCE_DOUBLE',
        'COERCE__INT64',
        'COERCE_UNSIGNED_INT',
        'COERCE_UNSIGNED_INT64'
    ]
    return type_name in TYPES

def is_fn_std_type(type_name):
    TYPES = [
        'abort',
        'abs',
        'acos',
        'asctime',
        'asin',
        'assert',
        'atan',
        'atan2',
        'atexit',
        'atof',
        'atoi',
        'atol',
        'bsearch',
        'calloc',
        'ceil',
        'clearerr',
        'clock',
        'cos',
        'cosh',
        'ctime',
        'difftime',
        'div',
        'exit',
        'exp',
        'fabs',
        'fclose',
        'feof',
        'ferror',
        'fflush',
        'fgetc',
        'fgetpos',
        'fgets',
        'floor',
        'fmod',
        'fopen',
        'fprintf',
        'fputc',
        'fputs',
        'fread',
        'free',
        'freopen',
        'frexp',
        'fscanf',
        'fseek',
        'fsetpos',
        'ftell',
        'fwrite',
        'getc',
        'getchar',
        'getenv',
        'gets',
        'gmtime',
        'isalnum',
        'isalpha',
        'iscntrl',
        'isdigit',
        'isgraph',
        'islower',
        'isprint',
        'ispunct',
        'isspace',
        'isupper',
        'isxdigit',
        'labs',
        'ldexp',
        'ldiv',
        'localeconv',
        'localtime',
        'log',
        'log10',
        'longjmp',
        'malloc',
        'mblen',
        'mbstowcs',
        'mbtowc',
        'memchr',
        'memcmp',
        'memcpy',
        'memmove',
        'memset',
        'mktime',
        'modf',
        'perror',
        'pow',
        'printf',
        'putc',
        'putchar',
        'puts',
        'qsort',
        'raise',
        'rand',
        'realloc',
        'remove',
        'rename',
        'rewind',
        'scanf',
        'setbuf',
        'setjmp',
        'setlocale',
        'setvbuf',
        'signal',
        'sin',
        'sinh',
        'sprintf',
        'sqrt',
        'srand',
        'sscanf',
        'strcat',
        'strchr',
        'strcmp',
        'strcoll',
        'strcpy',
        'strcspn',
        'strerror',
        'strftime',
        'strlen',
        'strncat',
        'strncmp',
        'strncpy',
        'strpbrk',
        'strrchr',
        'strspn',
        'strstr',
        'strtod',
        'strtok',
        'strtol',
        'strtoul',
        'strxfrm',
        'system',
        'tan',
        'tanh',
        'time',
        'tmpfile',
        'tmpnam',
        'tolower',
        'toupper',
        'ungetc',
        'va_arg',
        'va_end',
        'va_start',
        'vfprintf',
        'vprintf',
        'vsprintf',
        'wcstombs',
        'wctomb'
    ]
    return type_name in TYPES    

def is_fn_hlp_type(type_name):
    TYPES = [
        '__FYL2X__', 
        '__FSCALE__',
        '__F2XM1__',
        '__ROL1__',
        '__ROL2__',
        '__ROL4__',
        '__ROL8__',
        '__ROR1__',
        '__ROR2__',
        '__ROR4__',
        '__ROR8__',
        '__CS__',
        '__SS__',
        '__DS__',
        '__ES__',
        '__FS__',
        '__GS__',
        '__CFSHR__',
        '__CFSHL__',
        '__CFADD__',
        '__OFADD__',
        '__OFSUB__',
        '__SETP__',
        '__FSCALE__',
        'JUMPOUT',
        'BUG',
        '__halt',
        '__fastfail',
        '__debugbreak',
        '__rdtsc',
        '__readeflags',
        '__readfsdword',
        '__readgsdword',
        '__readfsqword',
        '__readgsqword',
        '__writeeflags',
        '__writefsdword',
        '__writegsdword',
        '__writefsqword',
        '__writegsqword'
    ]
    return type_name in TYPES    
 
def get_fn_type(type_name):
    if is_fn_typ_type(type_name):
        return "typ"
    elif is_fn_std_type(type_name):
        return "std"
    elif is_fn_hlp_type(type_name):
        return "hlp"
    else:
        return "usr"

def extract_calls_from_decompiled(func_ea):
    # Get statistics on calls originating from a single function.
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return {}

    class CallVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self, cfunc):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.calls = collections.defaultdict(dict)
            self.cfunc = cfunc

        def visit_expr(self, expr):
            # called by `apply_to()`
            if expr.op == ida_hexrays.cot_call:
                try:
                    callee_addr = expr.x.obj_ea
                except Exception:
                    callee_addr = -1

                args = []

                for arg in expr.a:
                    try:
                        arg_type = arg.type.dstr() if arg.type else "<unknown>"
                        arg_name = arg.print1(self.cfunc)
                    except Exception:
                        arg_type = "<unknown>"
                        arg_name = "<unknown>"

                    args.append({
                        "name": idaapi.tag_remove(arg_name),
                        "type": arg_type
                    })

                # The same function can be called from different locations within the given function, 
                # each with a unique set of parameters.
                self.calls[callee_addr][expr.ea] = args
            return 0

    visitor = CallVisitor(cfunc)
    visitor.apply_to(cfunc.body, None)

    return dict(visitor.calls)
