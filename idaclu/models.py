from re import split

from idaclu.qt_shims import (
    QAbstractItemModel,
    QBrush,
    QColor,
    QModelIndex,
    Qt,
    QtCore
)


class ResultNode(object):
    def __init__(self, data, parent=None):
        if isinstance(data, tuple):
            self._data = list(data)
        elif isinstance(data, str) or not hasattr(data, '__getitem__'):
            # data is not indexable
            self._data = [data]
        else:
            self._data = data

        self._col_count = len(self._data)
        self._children = []
        self._parent = parent

    def data(self, col):
        # len(self._data) - actual column count
        # self.columnCount() - column allocation for the node
        if 0 <= col < len(self._data):
            _data = self._data[col]
            return str(_data) if _data != None else ""

    def columnCount(self):
        return self._col_count

    def childCount(self):
        return len(self._children)

    def child(self, row):
        if 0 <= row < self.childCount():
            return self._children[row]

    def parent(self):
        return self._parent

    def row(self):
        return self.childCount()

    def addChild(self, child):
        child._parent = self
        self._children.append(child)
        self._col_count = max(child.columnCount(), self._col_count)

    def setData(self, col, val):
        if 0 <= col < len(self._data):
            self._data[col] = val
            return True
        return False

class ResultModel(QAbstractItemModel):

    def __init__(self, heads, nodes, env_desc):
        super(ResultModel, self).__init__()
        self.env = env_desc
        self.iroot = ResultNode([])
        self.heads = heads
        self.bg_col = heads.index('Color') if 'Color' in heads else None
        for node in nodes:
            self.iroot.addChild(node)

    def rowCount(self, parent_idx=QModelIndex()):
        parent_item = self.getItem(parent_idx)
        return parent_item.childCount()

    def addChild(self, data, parent_idx=QModelIndex()):
        parent_item = self.getItem(parent_idx)
        child_item = None
        is_obj = isinstance(data, ResultNode)
        child_item = data if is_obj else ResultNode(data, parent_item)
        parent_item.addChild(child_item)

    def index(self, row, col, _parent=QModelIndex()):
        parent = self.getItem(_parent)

        if not self.hasIndex(row, col, _parent):
            return QModelIndex()

        child = parent.child(row)
        if child:
            return self.createIndex(row, col, child)
        return QModelIndex()

    def parent(self, index):
        if index.isValid():
            child_item = self.getItem(index)
            parent_item = child_item.parent()
            if parent_item == self.iroot:
                return QModelIndex()
            return self.createIndex(parent_item.row(), 0, parent_item)
        # Return an invalid QModelIndex() to indicate "no parent."
        return QModelIndex()

    def columnCount(self, parent_idx=QModelIndex()):
        parent_item = self.getItem(parent_idx)
        return parent_item.columnCount()

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        node = self.getItem(index)

        if role == Qt.DisplayRole:
            col = index.column()
            data = node.data(col)
            return data.replace('%', '_') if self.heads[col] == 'Name' else data
        elif role == Qt.BackgroundRole:
            rgb_string = node.data(self.bg_col)
            if rgb_string and rgb_string != 'rgb(255,255,255)':
                r, g, b = map(int, rgb_string.removeprefix("rgb(").removesuffix(")").split(","))
                color = QColor(r, g, b)
                if self.env.lib_qt == 'pyqt5':
                    return color
                elif self.env.lib_qt == 'pyside':
                    brush = QBrush(color)
                    return brush
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.heads[section]
        return None

    def flags(self, index):
        return Qt.ItemIsSelectable | Qt.ItemIsEnabled | Qt.ItemIsEditable

    def setData(self, index, value, role=Qt.EditRole):
        if not index.isValid() or role != Qt.EditRole:
            return False

        item = self.getItem(index)
        set_col = index.column()
        lib_qt = self.env.lib_qt

        if value.startswith('rgb'):
            beg_col = 0
            end_col = set_col if lib_qt == 'pyqt5' else None
            roles = [Qt.BackgroundRole]
        else:
            beg_col = set_col
            end_col = set_col + 1 if lib_qt == 'pyqt5' else None
            roles = [Qt.EditRole]

        item.setData(set_col, value)
        beg_idx = index.sibling(index.row(), beg_col)
        if lib_qt == 'pyqt5':
            end_idx = index.sibling(index.row(), end_col)
            self.dataChanged.emit(beg_idx, end_idx, roles)
        elif lib_qt == 'pyside':
            self.dataChanged.emit(beg_idx, roles)
        return True

    def getItem(self, index):
        if index and index.isValid():
            # Get the pointer to the item associated with the index.
            item = index.internalPointer()
            if item:
                return item
        # Return the root item if the index is invalid.
        return self.iroot
