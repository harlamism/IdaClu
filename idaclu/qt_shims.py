# Shim file to support PySide v1.x (Qt4), PyQt v5.x (Qt5) and PySide v6.x (Qt6)
# Documentation provided by Qt and Riverbank Computing Ltd.:
#  - https://srinikom.github.io/pyside-docs/
#  - https://doc.qt.io/qtforpython-5/
#  - https://doc.qt.io/qtforpython-6/
# Inspired by the gist of Willi Ballenthin:
#  - https://gist.github.com/williballenthin/277eedca569043ef0984
#
# Binding resolution order:
#  1. PySide6 (Qt6)  - IDA 9.2 and newer
#  2. PyQt5   (Qt5)  - IDA 6.9 through 9.1
#  3. PySide  (Qt4)  - IDA 6.8 and older
#
# The old IDA <= 6.8 check is kept exactly as before, since PySide (Qt4)
# is only ever expected there. For every newer IDA, PySide6 is tried
# first and PyQt5 is used as a fallback whenever PySide6 cannot be
# imported (missing package, or the "GUI version of IDA only" guard
# that IDA's bundled PySide6 raises as an ImportError outside idaq).


import importlib


is_ida = True
try:
    import idaapi
except ImportError:
    is_ida = False


BINDING_PYSIDE6 = 'pyside6'  # Qt6
BINDING_PYQT5 = 'pyqt5'      # Qt5
BINDING_PYSIDE = 'pyside'    # Qt4

_PACKAGE_NAMES = {
    BINDING_PYSIDE6: 'PySide6',
    BINDING_PYQT5: 'PyQt5',
    BINDING_PYSIDE: 'PySide',
}


def _detect_binding():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        return BINDING_PYSIDE
    try:
        import PySide6
        return BINDING_PYSIDE6
    except ImportError:
        return BINDING_PYQT5


_BINDING = _detect_binding()


def _qt_module(submodule_name):
    package_name = _PACKAGE_NAMES[_BINDING]
    return importlib.import_module(package_name + '.' + submodule_name)


# Table of every exported class/name that lives at a fixed spot inside
# QtCore/QtGui/QtWidgets, keyed by name, with a (qt4_module, qt5_module)
# pair as the value. PySide6 (Qt6) reuses the qt5_module column unless
# the name shows up in _QT6_MODULE_OVERRIDES below.
_CLASS_MODULES = {
    'QAbstractItemModel':    ('QtCore', 'QtCore'),
    'QAbstractItemView':     ('QtGui', 'QtWidgets'),
    'QAction':               ('QtGui', 'QtWidgets'),
    'QApplication':          ('QtGui', 'QtWidgets'),
    'QBrush':                ('QtGui', 'QtGui'),
    'QByteArray':            ('QtCore', 'QtCore'),
    'QCheckBox':             ('QtGui', 'QtWidgets'),
    'QColor':                ('QtGui', 'QtGui'),
    'QComboBox':             ('QtGui', 'QtWidgets'),
    'QCompleter':            ('QtGui', 'QtWidgets'),
    'QCoreApplication':      ('QtCore', 'QtCore'),
    'QCursor':               ('QtGui', 'QtGui'),
    'QDialog':               ('QtGui', 'QtWidgets'),
    'QEvent':                ('QtCore', 'QtCore'),
    'QFont':                 ('QtGui', 'QtGui'),
    'QFrame':                ('QtGui', 'QtWidgets'),
    'QGroupBox':             ('QtGui', 'QtWidgets'),
    'QHeaderView':           ('QtGui', 'QtWidgets'),
    'QHBoxLayout':           ('QtGui', 'QtWidgets'),
    'QIcon':                 ('QtGui', 'QtGui'),
    'QImage':                ('QtGui', 'QtGui'),
    'QLabel':                ('QtGui', 'QtWidgets'),
    'QListView':             ('QtGui', 'QtWidgets'),
    'QLineEdit':             ('QtGui', 'QtWidgets'),
    'QMainWindow':           ('QtGui', 'QtWidgets'),
    'QMenu':                 ('QtGui', 'QtWidgets'),
    'QMessageBox':           ('QtGui', 'QtWidgets'),
    'QMetaObject':           ('QtCore', 'QtCore'),
    'QModelIndex':           ('QtCore', 'QtCore'),
    'QPainter':              ('QtGui', 'QtGui'),
    'QPixmap':               ('QtGui', 'QtGui'),
    'QPoint':                ('QtCore', 'QtCore'),
    'QPointF':               ('QtCore', 'QtCore'),
    'QProgressBar':          ('QtGui', 'QtWidgets'),
    'QPushButton':           ('QtGui', 'QtWidgets'),
    'QRadioButton':          ('QtGui', 'QtWidgets'),
    'QRect':                 ('QtCore', 'QtCore'),
    'QScrollArea':           ('QtGui', 'QtWidgets'),
    'QSize':                 ('QtCore', 'QtCore'),
    'QSizePolicy':           ('QtGui', 'QtWidgets'),
    'QSortFilterProxyModel': ('QtGui', 'QtCore'),
    'QSlider':               ('QtGui', 'QtWidgets'),
    'QSpacerItem':           ('QtGui', 'QtWidgets'),
    'QSplitter':             ('QtGui', 'QtWidgets'),
    'QStandardItem':         ('QtGui', 'QtGui'),
    'QStandardItemModel':    ('QtGui', 'QtGui'),
    'QStringListModel':      ('QtGui', 'QtCore'),
    'QStyle':                ('QtGui', 'QtWidgets'),
    'QStyledItemDelegate':   ('QtGui', 'QtWidgets'),
    'QStyleFactory':         ('QtGui', 'QtWidgets'),
    'QStyleOptionComboBox':  ('QtGui', 'QtWidgets'),
    'QStyleOptionSlider':    ('QtGui', 'QtWidgets'),
    'Qt':                    ('QtCore', 'QtCore'),
    'QTableWidget':          ('QtGui', 'QtWidgets'),
    'QTableWidgetItem':      ('QtGui', 'QtWidgets'),
    'QTabWidget':            ('QtGui', 'QtWidgets'),
    'QTextBrowser':          ('QtGui', 'QtWidgets'),
    'QTextEdit':             ('QtGui', 'QtWidgets'),
    'QThread':               ('QtCore', 'QtCore'),
    'QTranslator':           ('QtCore', 'QtCore'),
    'QTreeView':             ('QtGui', 'QtWidgets'),
    'QTreeWidget':           ('QtGui', 'QtWidgets'),
    'QTreeWidgetItem':       ('QtGui', 'QtWidgets'),
    'QVBoxLayout':           ('QtGui', 'QtWidgets'),
    'QWidget':               ('QtGui', 'QtWidgets'),
}

# Names whose Qt6 (PySide6) submodule differs from the qt5_module column
# in _CLASS_MODULES above. QAction (like QShortcut, which this shim does
# not export) moved from QtWidgets to QtGui in Qt6.
_QT6_MODULE_OVERRIDES = {
    'QAction': 'QtGui',
}


def _class_submodule(name):
    qt4_module, qt5_module = _CLASS_MODULES[name]
    if _BINDING == BINDING_PYSIDE:
        return qt4_module
    if _BINDING == BINDING_PYSIDE6:
        return _QT6_MODULE_OVERRIDES.get(name, qt5_module)
    return qt5_module


def _resolve_class(name):
    submodule_name = _class_submodule(name)
    module = _qt_module(submodule_name)
    return getattr(module, name)


def _make_class_getter(name):
    def _getter():
        return _resolve_class(name)
    return _getter


for _class_name in _CLASS_MODULES:
    globals()['get_' + _class_name] = _make_class_getter(_class_name)
del _class_name


def get_DescendingOrder():
    QtCore = _qt_module('QtCore')
    if _BINDING == BINDING_PYSIDE:
        return QtCore.Qt.SortOrder.DescendingOrder
    else:
        return QtCore.Qt.DescendingOrder

def get_Signal():
    QtCore = _qt_module('QtCore')
    if _BINDING == BINDING_PYQT5:
        return QtCore.pyqtSignal
    else:
        return QtCore.Signal

def get_QtCore():
    return _qt_module('QtCore')

def get_QtGui():
    return _qt_module('QtGui')

def get_QtWidgets():
    if _BINDING == BINDING_PYSIDE:
        return None
    else:
        return _qt_module('QtWidgets')


DescendingOrder = get_DescendingOrder()
Signal = get_Signal()

QAbstractItemModel = get_QAbstractItemModel()
QAbstractItemView = get_QAbstractItemView()
QAction = get_QAction()
QApplication = get_QApplication()
QBrush = get_QBrush()
QByteArray = get_QByteArray()
QCheckBox = get_QCheckBox()
QColor = get_QColor()
QComboBox = get_QComboBox()
QCompleter = get_QCompleter()
QCoreApplication = get_QCoreApplication()
QCursor = get_QCursor()
QDialog = get_QDialog()
QEvent = get_QEvent()
QFont = get_QFont()
QFrame = get_QFrame()
QGroupBox = get_QGroupBox()
QHeaderView = get_QHeaderView()
QHBoxLayout = get_QHBoxLayout()
QIcon = get_QIcon()
QImage = get_QImage()
QLabel = get_QLabel()
QListView = get_QListView()
QLineEdit = get_QLineEdit()
QMainWindow = get_QMainWindow()
QMenu = get_QMenu()
QMessageBox = get_QMessageBox()
QMetaObject = get_QMetaObject()
QModelIndex = get_QModelIndex()
QPainter = get_QPainter()
QPixmap = get_QPixmap()
QPoint = get_QPoint()
QPointF = get_QPointF()
QProgressBar = get_QProgressBar()
QPushButton = get_QPushButton()
QRadioButton = get_QRadioButton()
QRect = get_QRect()
QScrollArea = get_QScrollArea()
QSize = get_QSize()
QSizePolicy = get_QSizePolicy()
QSortFilterProxyModel = get_QSortFilterProxyModel()
QSlider = get_QSlider()
QSpacerItem = get_QSpacerItem()
QSplitter = get_QSplitter()
QStandardItem = get_QStandardItem()
QStandardItemModel = get_QStandardItemModel()
QStringListModel = get_QStringListModel()
QStyle = get_QStyle()
QStyledItemDelegate = get_QStyledItemDelegate()
QStyleFactory = get_QStyleFactory()
QStyleOptionComboBox = get_QStyleOptionComboBox()
QStyleOptionSlider = get_QStyleOptionSlider()
Qt = get_Qt()
QTableWidget = get_QTableWidget()
QTableWidgetItem = get_QTableWidgetItem()
QTabWidget = get_QTabWidget()
QtCore = get_QtCore()
QTextBrowser = get_QTextBrowser()
QTextEdit = get_QTextEdit()
QtGui = get_QtGui()
QThread = get_QThread()
QTranslator = get_QTranslator()
QTreeView = get_QTreeView()
QTreeWidget = get_QTreeWidget()
QTreeWidgetItem = get_QTreeWidgetItem()
QtWidgets = get_QtWidgets()
QVBoxLayout = get_QVBoxLayout()
QWidget = get_QWidget()
