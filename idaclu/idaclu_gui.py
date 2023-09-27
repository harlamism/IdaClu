import collections
import json
import os
import re
import sys
import time
#
import idc
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu.qt_shims import (
    QCoreApplication,
    QCursor,
    Qt,
    QFrame,
    QIcon,
    QLineEdit,
    QMenu,
    QPushButton,
    QSize,
    QSizePolicy,
    QSpacerItem,
    QStyledItemDelegate,
    QVBoxLayout,
    QWidget
)
from idaclu import ida_utils
from idaclu import plg_utils
from idaclu.ui_idaclu import Ui_PluginDialog
from idaclu.qt_utils import FrameLayout
from idaclu.models import ResultModel, ResultNode
from idaclu.assets import resource

# new backward-incompatible modules
try:
    import ida_dirtree
except ImportError:
    pass


class AppendTextEditDelegate(QStyledItemDelegate):
    def createEditor(self, parent, option, index):
        editor = QLineEdit(parent)
        return editor

    def setEditorData(self, editor, index):
        current_text = index.data()
        editor.setText(current_text)

    def setModelData(self, editor, model, index):
        current_text = index.data()
        new_text = editor.text()
        appended_text = "{}".format(new_text)
        model.setData(index, appended_text)
        func_addr = ida_shims.get_name_ea(0, current_text)
        ida_shims.set_name(func_addr, new_text, idaapi.SN_NOWARN)


class IdaCluDialog(QWidget):
    def __init__(self, env_desc):
        super(IdaCluDialog, self).__init__()
        self.env_desc = env_desc
        self.ui = Ui_PluginDialog()
        self.ui.setupUi(self)

        self.ui.ResultsView.setItemDelegate(AppendTextEditDelegate())

        self.is_sidebar_on_left = True
        self.is_filters_shown = True
        self.option_sender = None
        self.is_mode_recursion = False
        self.mode_merge = 'prefix'
        # values to initialize the corresponding filter

        if self.env_desc.feat_folders:
            self.folders = ida_utils.get_func_dirs('/')
            self.folders_funcs = ida_utils.get_dir_funcs(self.folders)

        self.prefixes = self.getFuncPrefs(is_dummy=True)
        self.sel_dirs = []
        self.sel_prfx = []
        self.sel_colr = []

        self.heads = ['Name', 'Address', 'Size', 'Chunks', 'Nodes', 'Edges', 'Comment', 'Color']
        if env_desc.feat_folders:
            self.heads.insert(1, 'Folder')

        sp_path = self.get_splg_root(self.env_desc.plg_loc, 'idaclu')
        for frame in self.get_sp_controls(sp_path):
            self.ui.ScriptsLayout.addWidget(frame)

        self.initFoldersFilter()
        self.initPrefixFilter()
        self.bindUiElems()
        self.applyStyling()

    def toggleRecursion(self):
        self.is_mode_recursion = not self.is_mode_recursion

    def bindUiElems(self):
        self.bindClicks()
        self.ui.ResultsView.doubleClicked.connect(self.treeDoubleClick)
        self.ui.ResultsView.customContextMenuRequested.connect(self.showContextMenu)

    def bindClicks(self):
        feat_folders = self.env_desc.feat_folders
        bind_data = [
            (self.ui.NameToggle, self.toggleModeMerge, feat_folders),
            (self.ui.ModeToggle, self.toggleRecursion, True),
            (self.ui.SetNameButton, self.addMerge, True),
            (self.ui.ClsNameButton, self.clsMerge, True),
            (self.ui.SetColorYellow, self.changeFuncColor, True),
            (self.ui.SetColorBlue, self.changeFuncColor, True),
            (self.ui.SetColorGreen, self.changeFuncColor, True),
            (self.ui.SetColorPink, self.changeFuncColor, True),
            (self.ui.SetColorNone, self.changeFuncColor, True),
            (self.ui.ScriptsHeader, self.swapPosition, True),
            (self.ui.FiltersHeader, self.showFilters, True)
        ]
        for (elem, meth, cond) in bind_data:
            if cond:
                elem.clicked.connect(meth)

    def applyStyling(self):
        self.ui.ModeToggle.setProperty('class','tool-btn tool-btn-hov')
        self.ui.NameEdit.setProperty('class','head-edit')
        self.ui.SetNameButton.setProperty('class','tool-btn tool-btn-hov')
        self.ui.ClsNameButton.setProperty('class','tool-btn tool-btn-hov')
        #
        self.ui.SetColorYellow.setProperty('class','plt-btn plt-btn-yellow')
        self.ui.SetColorBlue.setProperty('class','plt-btn plt-btn-blue')
        self.ui.SetColorGreen.setProperty('class','plt-btn plt-btn-green')
        self.ui.SetColorPink.setProperty('class','plt-btn plt-btn-pink')
        self.ui.SetColorNone.setProperty('class','plt-btn plt-btn-none')
        self.ui.PaletteYellow.setProperty('class','plt-btn plt-btn-yellow')
        self.ui.PaletteBlue.setProperty('class','plt-btn plt-btn-blue')
        self.ui.PaletteGreen.setProperty('class','plt-btn plt-btn-green')
        self.ui.PalettePink.setProperty('class','plt-btn plt-btn-pink')
        self.ui.PaletteNone.setProperty('class','plt-btn plt-btn-none')

    def getFuncPrefs(self, is_dummy=False):
        pfx_afacts = ['%', 'sub_']
        prefs = set()
        for func_addr in idautils.Functions():
            func_name = ida_shims.get_func_name(func_addr)
            if any(pa in func_name for pa in pfx_afacts):
                func_prefs = ida_utils.get_func_prefs(func_name, True, is_dummy)
                prefs.update(func_prefs)
        return list(prefs)

    def viewSelChanged(self):
        self.ui.SetNameButton.setEnabled(True)
        self.ui.ClsNameButton.setEnabled(True)
        self.ui.SetColorYellow.setEnabled(True)
        self.ui.SetColorBlue.setEnabled(True)
        self.ui.SetColorGreen.setEnabled(True)
        self.ui.SetColorPink.setEnabled(True)
        self.ui.SetColorNone.setEnabled(True)

    def initPrefixFilter(self):
        self.ui.PrefixSelect.addItems(self.prefixes)
        self.ui.PrefixSelect.lineEdit().setText("")

    def initFoldersFilter(self):
        if self.env_desc.feat_folders:
            if len(self.folders) == 0:
                self.ui.FolderSelect.setEnabled(False)
                # leave "as-is"
                # do not populate the corresponding combo-box
            else:
                # leave "as-is"
                # do not disable the corresponding combo-box
                self.ui.FolderSelect.addItems(self.folders)

            # do not print initial value
            self.ui.FolderSelect.lineEdit().setText("")
            # default pointing cursor and
            # hoverable button
            self.ui.NameToggle.setProperty('class','tool-btn tool-btn-hov edit-head')
        else:
            self.ui.FolderHeader.setParent(None)
            self.ui.FolderSelect.setParent(None)
            self.ui.FolderFilter.setParent(None)
            # graceful degradation -
            # button does not appear as clickable
            self.ui.NameToggle.setCursor(QCursor(Qt.ArrowCursor))
            self.ui.NameToggle.setProperty('class','tool-btn edit-head')
            layout = self.ui.FiltersAdapter
            item = layout.takeAt(0)
            if item:
                widget = item.widget()
                if widget:
                    widget.deleteLater()
                del item

    def getSelectedColors(self):
        colors = []
        if self.ui.PaletteYellow.isChecked():
            colors.append(plg_utils.RgbColor((255,255,191)))
        if self.ui.PaletteBlue.isChecked():
            colors.append(plg_utils.RgbColor((199,255,255)))
        if self.ui.PaletteGreen.isChecked():
            colors.append(plg_utils.RgbColor((191,255,191)))
        if self.ui.PalettePink.isChecked():
            colors.append(plg_utils.RgbColor((255,191,239)))
        if self.ui.PaletteNone.isChecked():
            colors.append(plg_utils.RgbColor((255,255,255)))
        return colors

    def get_plugin_data(self):
        def sort_with_progress(constant, mcounter):
            def custom_sort(item):
                index, element = item
                mcounter[0] += 1
                finished = 65 + int(15 * (mcounter[0] / float(constant)))
                self.ui.worker.updateProgress.emit(finished)
                return element['func_size']
            return custom_sort

        sender_button = self.sender()

        full_spec_name = sender_button.objectName()
        elem, cat, plg = full_spec_name.split('#')

        root_folder = self.env_desc.plg_loc
        module = None
        with plg_utils.PluginPath(os.path.join(root_folder, 'idaclu', 'plugins', cat)):
            module = __import__(plg)
            del sys.modules[plg]

        script_name = getattr(module, 'SCRIPT_NAME')
        script_type = getattr(module, 'SCRIPT_TYPE', 'custom')
        script_view = getattr(module, 'SCRIPT_VIEW', 'table')
        script_args = getattr(module, 'SCRIPT_ARGS', [])

        plug_params = {}
        if self.option_sender != None:
            widget = self.ui.ScriptsArea.findChild(QPushButton, self.option_sender)
            parent_layout = widget.parent().layout()

            if self.option_sender == full_spec_name:
                for i in range(parent_layout.count()):
                    sub_item = parent_layout.itemAt(i)
                    if sub_item:
                        sub_widget = sub_item.widget()
                        if sub_widget and (isinstance(sub_widget, QLineEdit)):
                            param_name = sub_widget.objectName().replace("{}__".format(full_spec_name), "")
                            plug_params[param_name] = sub_widget.text()  # .toPlainText()

            for i in range(parent_layout.count()):
                sub_item = parent_layout.itemAt(i)
                if sub_item:
                    if isinstance(sub_item, QSpacerItem):
                        parent_layout.removeItem(sub_item)
                        continue
                    sub_widget = sub_item.widget()
                    if sub_widget and (isinstance(sub_widget, QLineEdit)):
                        parent_layout.removeWidget(sub_widget)
                        sub_widget.setParent(None)

            self.option_sender = None

        elif self.option_sender == None and len(script_args) > 0:
            parent_widget = sender_button.parent()
            if parent_widget:
                for i, (ctrl_name, var_name, ctrl_ph) in enumerate(script_args):
                    text_edit = QLineEdit()
                    text_edit.setPlaceholderText(ctrl_ph)
                    text_edit.setMaximumSize(QSize(16777215, 30))
                    parent_widget.layout().addWidget(text_edit)
                    text_edit.setObjectName("{}__{}".format(full_spec_name, var_name))
                spacer = QSpacerItem(20, 30, QSizePolicy.Fixed, QSizePolicy.MinimumExpanding)
                parent_widget.layout().addStretch(1)
                self.option_sender = full_spec_name
                return

        agroup = getattr(module, 'get_data')

        is_filter_embed = False
        if script_type == 'func':
            is_filter_embed = True
            sdata = agroup(self.updatePbFunc, self.env_desc, plug_params)  # pre-filter
        elif script_type == 'custom':
            is_filter_embed = False
            sdata = agroup(self.updatePb, self.env_desc, plug_params)  # post-filter
        else:
            ida_shims.msg('ERROR: Unknown plugin type')
            return
        sitems = None

        self.items = []

        sdatt = collections.defaultdict(list)
        overall_count = sum(len(lst) for lst in sdata.values())
        global_index = 0
        for dt in sdata:
            for tt in sdata[dt]:
                func_addr = None
                func_comm = None
                if isinstance(tt, int):
                    func_addr = tt
                    func_comm = ""
                elif self.env_desc.ver_py == 2 and isinstance(tt, long):
                    func_addr = int(tt)
                    func_comm = ""
                elif isinstance(tt, tuple):
                    func_addr = int(tt[0])
                    func_comm = tt[1]

                if is_filter_embed == False:
                    if not self.isFuncRelevant(func_addr):
                        continue

                node_count, edge_count = ida_utils.get_nodes_edges(func_addr)
                func_desc = idaapi.get_func(func_addr)
                func_name = ida_shims.get_func_name(func_addr)
                func_colr = ida_shims.get_color(func_addr, idc.CIC_FUNC)
                func_path = None
                if self.env_desc.feat_folders:
                    func_path = self.folders_funcs[func_addr] if func_addr in self.folders_funcs else '/'

                entry = collections.OrderedDict()
                entry['func_name'] = func_name
                if func_path:
                    entry['func_path'] = func_path
                entry['func_addr'] = hex(int(func_addr))
                entry['func_size'] = ida_shims.calc_func_size(func_desc)
                entry['func_chnk'] = len(list(idautils.Chunks(func_addr)))
                entry['func_node'] = node_count
                entry['func_edge'] = edge_count
                entry['func_comm'] = func_comm
                entry['func_colr'] = plg_utils.RgbColor(func_colr).get_to_str()

                sdatt[dt].append(entry)
                global_index += 1
                finished = 50 + int(15 * (global_index / float(overall_count)))
                self.ui.worker.updateProgress.emit(finished)

        mut_counter = [0]
        for key, value in sdatt.items():
            sdatt[key] = sorted(enumerate(value), key=sort_with_progress(overall_count, mut_counter))

        global_index = 0
        for dt in sdatt:
            self.items.append(ResultNode("{} ({})".format(dt, len(sdatt[dt]))))
            for (idx, tt) in sdatt[dt]:
                self.items[-1].addChild(ResultNode(list(tt.values())))
                global_index += 1
                finished = 80 + int(15 * (global_index / float(overall_count)))
                self.ui.worker.updateProgress.emit(finished)


        self.some_options_shown = None
        self.ui.ResultsView.setModel(ResultModel(self.heads, self.items, self.env_desc))
        self.ui.worker.updateProgress.emit(100)
        self.prepareView()

    def prepareView(self):
        self.ui.ResultsView.setColumnHidden(self.heads.index('Color'), True)
        # color component values; irrelevant
        resultsViewSelModel = self.ui.ResultsView.selectionModel()
        resultsViewSelModel.selectionChanged.connect(self.viewSelChanged)
        self.ui.ResultsView.header().resizeSection(0, 240)
        self.ui.ResultsView.header().resizeSection(1, 96)
        self.ui.ResultsView.header().resizeSection(2, 96)
        self.ui.ResultsView.header().resizeSection(3, 96)

    def updatePb(self, curr_idx, total_count):
        finished = int(70 * (curr_idx / float(total_count)))
        self.ui.worker.updateProgress.emit(finished)

    def updatePbFunc(self):
        self.sel_dirs = self.ui.FolderSelect.getData().split('; ')
        self.sel_prfx = self.ui.PrefixSelect.getData().split('; ')
        self.sel_colr = self.getSelectedColors()

        func_desc = list(idautils.Functions())
        func_count = len(func_desc)
        for func_idx, func_addr in enumerate(func_desc):

            if not self.isFuncRelevant(func_addr):
                continue

            finished = int(50 * (func_idx/float(func_count)))
            self.ui.worker.updateProgress.emit(finished)
            yield func_addr

    def isFuncRelevant(self, func_addr):
        # function directories
        if len(self.sel_dirs) and self.sel_dirs[0] != '':
            if not (func_addr in self.folders_funcs and
                self.folders_funcs[func_addr] in self.sel_dirs):
                return False
        # function name prefixes
        func_name = ida_shims.get_func_name(func_addr)
        func_prfx = ida_utils.get_func_prefs(func_name, True, True)
        if len(self.sel_prfx) and self.sel_prfx[0] != '':
            if not any(p in self.sel_prfx for p in func_prfx):
                return False
        # function highlight color
        func_colr = plg_utils.RgbColor(ida_shims.get_color(func_addr, idc.CIC_FUNC))
        if len(self.sel_colr):
            if not any(func_colr == c for c in self.sel_colr):
                return False
        return True

    def treeDoubleClick(self, index):
        if not index.isValid():
            return None
        addr_index = index.sibling(index.row(), self.getFuncAddrCol())
        cell_data = addr_index.data()
        if cell_data and cell_data.startswith('0x'):
            idaapi.jumpto(plg_utils.from_hex(cell_data))

    def addMerge(self):
        address_col = self.heads.index('Address')
        merge_name = self.ui.NameEdit.text()
        if self.env_desc.feat_folders and self.mode_merge == 'folder':
            ida_utils.create_folder(merge_name)
            self.ui.FolderSelect.addItemNew("/{}".format(merge_name))
        elif self.mode_merge == 'prefix':
            self.ui.PrefixSelect.addItemNew(merge_name)

        captured_addr = []
        # gather only the selected function addresses
        if self.ui.ResultsView.selectionModel().hasSelection():
            indexes = [idx for idx in self.ui.ResultsView.selectionModel().selectedRows()]
            fields = [idx.sibling(idx.row(), address_col).data() for idx in indexes]

            func_dir = None
            if self.env_desc.feat_folders:
                func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
                func_dir.chdir('/')
            for idx, field in enumerate(fields):
                # make sure fields in TreeView are not of <long> type
                func_addr = int(field, base=16)
                captured_addr.append(func_addr)
                func_name = ida_shims.get_func_name(func_addr)

                if self.mode_merge == 'prefix':
                    # assumed that prefixes must contain delimiter
                    func_name_new = plg_utils.add_prefix(func_name, merge_name, False)
                    func_name_shadow = plg_utils.add_prefix(func_name, merge_name, True)
                    ida_shims.set_name(func_addr, func_name_new, idaapi.SN_CHECK)
                    self.ui.ResultsView.model().setData(indexes[idx], func_name_shadow)
                else:  # folder
                    func_dir.rename(func_name, '/{}/{}'.format(merge_name, func_name))
                    self.ui.ResultsView.model().setData(indexes[idx], str("/" + merge_name))

        # if recursion mode is enabled - find all calees
        additional_addr = []
        if self.is_mode_recursion == True:
            for func_addr in captured_addr:
                additional_addr.extend(ida_utils.recursive_prefix(func_addr))

            for func_addr in additional_addr:
                func_name = ida_shims.get_func_name(func_addr)
                if self.mode_merge == 'prefix':
                    func_name_new = merge_name + func_name
                    ida_shims.set_name(func_addr, func_name_new, idaapi.SN_CHECK)
                else:  # folder
                    func_dir.rename(func_name, '/{}/{}'.format(merge_name, func_name))

        if self.env_desc.feat_folders:
            self.folders = ida_utils.get_func_dirs('/')
            self.folders_funcs = ida_utils.get_dir_funcs(self.folders)

        ida_utils.refresh_ui()

    def getTableAddr(self):
        if self.ui.ResultsView.selectionModel().hasSelection():
            indexes = [index for index in self.ui.ResultsView.selectionModel().selectedRows()]
            for index in indexes:
                addr_str = index.sibling(index.row(), self.getFuncAddrCol()).data()
                addr_int = int(addr_str, base=16)
                yield addr_int

    def clsMerge(self):
        if self.ui.ResultsView.selectionModel().hasSelection():
            indexes = [index for index in self.ui.ResultsView.selectionModel().selectedRows()]
            data = [index.sibling(index.row(), self.getFuncAddrCol()).data() for index in indexes]
            pfx = self.ui.NameEdit.text()
            for idx, addr_field in enumerate(data):
                func_addr = int(addr_field, base=16)
                func_name = ida_shims.get_func_name(func_addr)
                if self.mode_merge == 'prefix':
                    func_prefs = ida_utils.get_func_prefs(func_name, True, True)
                    if len(func_prefs) == 1 and func_prefs[0] == 'sub_':
                        pass
                        # ida_shims.set_name(func_addr, "", idaapi.SN_NOWARN)
                        # clear all scenario ;)
                    else:
                        # get last prefix
                        name_token = str(func_prefs[0]).replace('_', '%')
                        func_name_new = func_name.replace(name_token, '')
                        ida_shims.set_name(func_addr, func_name_new, idaapi.SN_NOWARN)
                        self.ui.ResultsView.model().setData(indexes[idx], func_name_new)
                elif self.mode_merge == 'folder':
                    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
                    func_dir.chdir('/')
                    if func_addr in self.folders_funcs:
                        func_fldr = self.folders_funcs[func_addr]
                        func_path_old = '{}/{}'.format(func_fldr, func_name)
                        func_path_new = '/{}'.format(func_name)
                        func_dir.rename(func_path_old, func_path_new)
                        self.ui.ResultsView.model().setData(indexes[idx], '/')
                else:
                    ida_shims.msg('ERROR: unknown label mode')

    def showContextMenu(self, point):
        ix = self.ui.ResultsView.indexAt(point)
        if ix.column() == 0:
            menu = QMenu()
            menu.addAction(QIcon(':/idaclu/icon_64.png'), "Rename")
            action = menu.exec_(self.ui.ResultsView.mapToGlobal(point))
            if action:
                if action.text() == "Rename":
                    self.ui.ResultsView.edit(ix)

    def getFuncAddrCol(self):
        if self.env_desc.feat_folders:
            return 2
        else:
            return 1

    def changeFuncColor(self):
        sender_button = self.sender()
        btn_name = sender_button.objectName()
        color = None
        if btn_name == 'SetColorBlue':
            color = plg_utils.RgbColor((199,255,255), 'blue')
        elif btn_name == 'SetColorYellow':
            color = plg_utils.RgbColor((255,255,191), 'yellow')
        elif btn_name == 'SetColorGreen':
            color = plg_utils.RgbColor((191,255,191), 'green')
        elif btn_name == 'SetColorPink':
            color = plg_utils.RgbColor((255,191,239), 'pink')
        elif btn_name == 'SetColorNone':
            color = plg_utils.RgbColor((255,255,255), 'white')
        else:
            ida_shims.msg('ERROR: unknown palette button')

        if self.ui.ResultsView.selectionModel().hasSelection():
            indexes = [index for index in self.ui.ResultsView.selectionModel().selectedRows()]
            data = [index.sibling(index.row(), self.getFuncAddrCol()).data() for index in indexes]

            pfx = self.ui.NameEdit.text()
            for idx, va_str in enumerate(data):
                va = int(va_str, base=16)
                ida_shims.set_color(va, idc.CIC_FUNC, color.get_to_int())
                self.ui.ResultsView.model().setData(indexes[idx], color.get_to_str())

    def swapPosition(self):
        layout = self.ui.splitter
        if not self.env_desc.feat_ida6:
            self.ui.SidebarFrame.setParent(None)
            self.ui.ContentFrame.setParent(None)
        else:
            self.clearLayout(layout)

        if not self.is_sidebar_on_left:
            layout.insertWidget(0, self.ui.SidebarFrame)
            layout.insertWidget(1, self.ui.ContentFrame)
        else:
            layout.insertWidget(0, self.ui.ContentFrame)
            layout.insertWidget(1, self.ui.SidebarFrame)

        layout.setCollapsible(0,False)
        layout.setCollapsible(1,False)

        self.is_sidebar_on_left = not self.is_sidebar_on_left

    def clearLayout(self, layout):
        if layout is not None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()
                # else:
                #     self.clearLayout(item.layout())
                del item

    def toggleModeMerge(self):
        _translate = QCoreApplication.translate
        btn_caption = None
        edit_placeholder = None
        if self.mode_merge == 'prefix':
            btn_caption = "FOLDER"
            edit_placeholder = 'Insert name'
        else:  # 'folder'
            btn_caption = "PREFIX"
            edit_placeholder = 'Insert prefix'
        self.ui.NameToggle.setText(_translate(btn_caption, btn_caption, None))
        self.ui.NameEdit.setPlaceholderText(edit_placeholder)

        self.mode_merge = 'folder' if self.mode_merge == 'prefix' else 'prefix'

    def showFilters(self):
        if not self.is_filters_shown:
            self.ui.FiltersGroup.setMinimumSize(QSize(16777215, 16777215))
            self.ui.FiltersGroup.setMaximumSize(QSize(16777215, 16777215))
        else:
            self.ui.FiltersGroup.setMinimumSize(QSize(16777215, 1))
            self.ui.FiltersGroup.setMaximumSize(QSize(16777215, 1))

        self.is_filters_shown = not self.is_filters_shown

    def get_splg_root(self, plg_path, plg_fldr):
        splg_root = os.path.join(plg_path, plg_fldr, 'plugins')
        return splg_root

    def get_splg_tree(self, plg_splg_path):
        plg_tree = {}
        if os.path.exists(plg_splg_path):
            plg_tree = plg_utils.get_ordered_folder_tree(plg_splg_path)
        return plg_tree

    def is_sp_fname(self, sp_fname):
        return sp_fname.startswith('plugin_') and sp_fname.endswith('.py') and sp_fname != '__init__.py'

    def get_sp_controls(self, sp_path):
        sp_tree = self.get_splg_tree(sp_path)

        # depth of folder tree containing plugins is known
        for gdx, spg_ref in enumerate(sp_tree):
            if len(sp_tree[spg_ref]):
                spg_path = str(os.path.join(sp_path, spg_ref))
                spg_name = getattr(plg_utils.import_path(spg_path), 'PLUGIN_GROUP_NAME')
                spg_title = '{}. {}'.format(str(gdx+1), spg_name)

                spg_layout = FrameLayout(title=spg_title, env=self.env_desc)
                spg_layout.setProperty('class', 'frame')
                for sp_fname in sp_tree[spg_ref]:
                    plg_btn = None
                    if not self.is_sp_fname(sp_fname):
                        continue
                    sp_bname = sp_fname.replace('.py', '')
                    sp_name = sp_bname
                    # initial name is equal to file base name
                    # in case name will be not defined in plugin

                    sp_module = None
                    spe_msg = ""
                    # make sub-plugin discoverable in its group for importing
                    with plg_utils.PluginPath(os.path.join(sp_path, spg_ref)):
                        is_plug_ok = False
                        try:
                            sp_module = __import__(sp_bname)
                            del sys.modules[sp_bname]
                        except ImportError as err:
                            # in case some dependency is sub-plugin is missing
                            # the corresponding button will be disabled and
                            # tooltip will show this error
                            module_name = None
                            if self.env_desc.ver_py == 3:
                                module_name = err.name
                            else:
                                module_name = err.args[0].rsplit(' ',1)[-1]  # there is no .name attribute for Python2
                            spe_msg = "Module not found: {}".format(module_name)
                            # Attempt to open the module as a text file
                            # at least to recover sub-plugin name
                            try:
                                with open(os.path.join(sp_path, spg_ref, sp_fname), 'r') as file:
                                    for line in file:
                                        match = re.search(r'SCRIPT_NAME\s*=\s*["\']([^"\']+)', line)
                                        if match:
                                            sp_name = match.group(1)
                                            # self.log.debug("Recovered SCRIPT_NAME:", sp_name)
                                            break
                                    else:
                                        pass
                                        # self.log.debug("SCRIPT_NAME definition was not found")
                            except FileNotFoundError:
                                pass
                                # self.log.debug("Module file not found")
                        else:
                            is_plug_ok = True

                    # an attempt to load sub-plugin finished
                    # let's draw a corresponding button
                    sp_name = getattr(sp_module, 'SCRIPT_NAME', sp_name)
                    sp_layout = QVBoxLayout()
                    sp_frame = QFrame()
                    sp_frame.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
                    sp_frame.setObjectName('Frame#{}#{}'.format(spg_ref, sp_bname))

                    sp_button = QPushButton(sp_name)
                    if is_plug_ok:
                        sp_button.clicked.connect(self.get_plugin_data)
                    else:
                        sp_button.setEnabled(False)
                        sp_button.setToolTip(spe_msg)

                    sp_button.setObjectName('Button#{}#{}'.format(spg_ref, sp_bname))
                    sp_layout.addWidget(sp_button)
                    sp_frame.setLayout(sp_layout)
                    spg_layout.addWidget(sp_frame)
                yield spg_layout
