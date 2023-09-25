from . import qt_shims


class ResultNode(object):
    def __init__(self, data):
        self._data = data
        if type(data) == tuple:
            self._data = list(data)
        if type(data) is str or not hasattr(data, '__getitem__'):
            self._data = [data]

        self._columncount = len(self._data)
        self._children = []
        self._parent = None
        self._row = 0

    def data(self, column):
        if column >= 0 and column < len(self._data):
            return self._data[column]

    def columnCount(self):
        return self._columncount

    def childCount(self):
        return len(self._children)

    def child(self, row):
        if row >= 0 and row < self.childCount():
            return self._children[row]

    def parent(self):
        return self._parent

    def row(self):
        return self._row

    def addChild(self, child):
        child._parent = self
        child._row = len(self._children)
        self._children.append(child)
        self._columncount = max(child.columnCount(), self._columncount)

    def setData(self, column, value):
        if column < 0 or column >= len(self._data):
            return False
        self._data[column] = value
        return True


class ResultModel(qt_shims.get_QAbstractItemModel()):

    def __init__(self, heads, nodes, env_desc):
        super(ResultModel, self).__init__()
        self._root = ResultNode(heads)
        self.env_desc = env_desc
        for node in nodes:
            self._root.addChild(node)

    def rowCount(self, index):
        if index.isValid():
            return index.internalPointer().childCount()
        return self._root.childCount()

    def addChild(self, node, _parent):
        if not _parent or not _parent.isValid():
            parent = self._root
        else:
            parent = _parent.internalPointer()
        parent.addChild(node)

    def index(self, row, column, _parent=None):
        if not _parent or not _parent.isValid():
            parent = self._root
        else:
            parent = _parent.internalPointer()

        if not qt_shims.get_QAbstractItemModel().hasIndex(self, row, column, _parent):
            return qt_shims.get_QModelIndex()()

        child = parent.child(row)
        if child:
            return qt_shims.get_QAbstractItemModel().createIndex(self, row, column, child)
        else:
            return qt_shims.get_QModelIndex()()

    def parent(self, index):
        if index.isValid():
            p = index.internalPointer().parent()
            if p:
                return qt_shims.get_QAbstractItemModel().createIndex(self, p.row(), 0, p)
        return qt_shims.get_QModelIndex()()

    def columnCount(self, index):
        if index.isValid():
            return index.internalPointer().columnCount()
        return self._root.columnCount()

    def data(self, index, role=qt_shims.get_Qt().DisplayRole):
        if not index.isValid():
            return None
        node = index.internalPointer()
        if role == qt_shims.get_Qt().DisplayRole:
            return node.data(index.column())

        elif role == qt_shims.get_Qt().BackgroundRole:
            node = index.internalPointer()
            rgb_string = node.data(8)
            if rgb_string and rgb_string != 'rgb(255,255,255)':
                rgb_values = rgb_string.replace("rgb(", "").replace(")", "")
                r, g, b = tuple(map(int, rgb_values.split(",")))
                return qt_shims.get_QColor()(r, g, b)
        return None

    def setHeaderData(self, section, orientation, value, role=qt_shims.get_Qt().EditRole):
        if role != qt_shims.get_Qt().EditRole or orientation != qt_shims.get_Qt().Horizontal:
            return False
        result = self._root.setData(section, value)
        if result:
            self.headerDataChanged.emit(orientation, section, section)
        return result

    def headerData(self, section, orientation, role=qt_shims.get_Qt().DisplayRole):
        if orientation == qt_shims.get_Qt().Horizontal and role == qt_shims.get_Qt().DisplayRole:
            return self._root.data(section)
        return None

    def flags(self, index):
        return qt_shims.get_Qt().ItemIsSelectable|qt_shims.get_Qt().ItemIsEnabled|qt_shims.get_Qt().ItemIsEditable

    def setData(self, index, value, role=qt_shims.get_Qt().EditRole):
        if not index.isValid():
            return False
        node = index.internalPointer()
        if role == qt_shims.get_Qt().EditRole:
            col = 1 if value.startswith('/') else 0
            col = 8 if value.startswith('rgb') else col
            result = node.setData(col, value)
            if result:
                if self.env_desc.lib_qt == 'pyqt5':
                    self.dataChanged.emit(index.sibling(index.row(), col), index.sibling(index.row(), col), [qt_shims.get_Qt().EditRole])
                elif self.env_desc.lib_qt == 'pyside':
                    self.dataChanged.emit(index.sibling(index.row(), col), index.sibling(index.row(), col))
            if col == 8:
                self.dataChanged.emit(index.sibling(index.row(), 0), index.sibling(index.row(), 7), [qt_shims.get_Qt().BackgroundRole])
            return True
        return False
