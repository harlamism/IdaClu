# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'idacludGBIJV.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

# from PySide2.QtCore import *
# from PySide2.QtGui import *
# from PySide2.QtWidgets import *
from idaclu.qt_shims import (
    Signal,
    QSizePolicy,
    QAbstractItemView,
    QComboBox,
    QCoreApplication,
    QCursor,
    QEvent,
    QFont,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QIcon,
    QLineEdit,
    QMetaObject,
    QProgressBar,
    QPushButton,
    QRect,
    QScrollArea,
    QSize,
    QSizePolicy,
    QSpacerItem,
    QSplitter,
    QStandardItem,
    QStyledItemDelegate,
    Qt,
    QThread,
    QTreeView,
    QVBoxLayout,
    QWidget
)
from idaclu.qt_utils import i18n

class Worker(QThread):
    updateProgress = Signal(int)

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        for i in range(1, 101):
            self.updateProgress.emit(i)
            time.sleep(0.01)

class CheckableComboBox(QComboBox):
    def __init__(self):
        super(CheckableComboBox, self).__init__()
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        self.closeOnLineEditClick = False
        self.lineEdit().installEventFilter(self)
        self.view().viewport().installEventFilter(self)
        self.model().dataChanged.connect(self.updateLineEditField)
        self.itemDelegate = QStyledItemDelegate(self)
        self.setItemDelegate(self.itemDelegate)

    def hidePopup(self):
        super(CheckableComboBox, self).hidePopup()
        self.startTimer(100)

    def addItems(self, items, itemList=None):
        for indx, text in enumerate(items):
            try:
                data = itemList[indx]
            except (TypeError, IndexError):
                data = None
            self.addItem(text, data)

    def addItemNew(self, text, userData=None):
        for row in range(self.model().rowCount()):
            item = self.model().item(row)
            if (item and (item.text() == text)) or (userData and item.data() == userData):
                return False
        self.addItem(text, userData)
        return True

    def addItem(self, text, userData=None):
        item = QStandardItem()
        item.setText(text)
        if not userData is None:
            item.setData(userData)
        item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable)
        item.setData(Qt.Unchecked, Qt.CheckStateRole)
        self.model().appendRow(item)

    def eventFilter(self, widget, event):
        if widget == self.lineEdit():
            if event.type() == QEvent.MouseButtonRelease:
                if self.closeOnLineEditClick:
                    self.hidePopup()
                else:
                    self.showPopup()
                return True
            return super(CheckableComboBox, self).eventFilter(widget, event)
        if widget == self.view().viewport():
            if event.type() == QEvent.MouseButtonRelease:
                indx = self.view().indexAt(event.pos())
                item = self.model().item(indx.row())

                if item.checkState() == Qt.Checked:
                    item.setCheckState(Qt.Unchecked)
                else:
                    item.setCheckState(Qt.Checked)
                return True
            return super(CheckableComboBox, self).eventFilter(widget, event)

    def updateLineEditField(self):
        text_container = []
        for i in range(self.model().rowCount()):
            if self.model().item(i).checkState() == Qt.Checked:
                text_container.append(self.model().item(i).text())
            text_string = '; '.join(text_container)
            self.lineEdit().setText(text_string)

    def getData(self):
        return self.lineEdit().text()

    def clearData(self):
        self.clear()


class Ui_PluginDialog(object):
    def setupUi(self, PluginDialog):
        if not PluginDialog.objectName():
            PluginDialog.setObjectName(u"PluginDialog")
        PluginDialog.resize(911, 449)

        icon = QIcon()
        icon.addFile(":/idaclu/icon_64.png", QSize(), QIcon.Normal, QIcon.Off)
        PluginDialog.setWindowIcon(icon)

        self.PluginAdapter = QHBoxLayout(PluginDialog)
        self.PluginAdapter.setObjectName(u"PluginAdapter")

        self.splitter = QSplitter()
        self.splitter.setOrientation(Qt.Horizontal)
        self.splitter.setObjectName("splitter")

        self.MainLayout = QHBoxLayout()
        self.MainLayout.setObjectName(u"MainLayout")

        self.SidebarFrame = QFrame(PluginDialog)
        self.SidebarLayout = QVBoxLayout(self.SidebarFrame)
        self.SidebarLayout.setSpacing(0)
        self.SidebarLayout.setObjectName(u"SidebarLayout")
        self.SidebarLayout.setContentsMargins(0, 0, 5, 0)

        self.ScriptsWidget = QVBoxLayout()
        self.ScriptsWidget.setSpacing(0)
        self.ScriptsWidget.setObjectName(u"ScriptsWidget")
        self.ScriptsHeader = QPushButton(PluginDialog)
        self.ScriptsHeader.setObjectName(u"ScriptsHeader")
        self.ScriptsHeader.setMinimumSize(QSize(0, 30))
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.ScriptsHeader.setFont(font)
        self.ScriptsHeader.setCursor(QCursor(Qt.PointingHandCursor))
        self.ScriptsHeader.setProperty('class', 'head')
        self.ScriptsWidget.addWidget(self.ScriptsHeader)

        self.ScriptsArea = QScrollArea(PluginDialog)
        self.ScriptsArea.setObjectName(u"ScriptsArea")
        self.ScriptsArea.setWidgetResizable(True)
        self.ScriptsArea.horizontalScrollBar().setEnabled(False)
        self.ScriptsArea.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.ScriptsContents = QWidget()
        self.ScriptsContents.setObjectName(u"ScriptsContents")
        self.ScriptsContents.setGeometry(QRect(0, 0, 215, 233))

        # custom
        # sub-plugin script buttons are added to the scrollable layout
        self.ScriptsLayout = QVBoxLayout(self.ScriptsContents)
        self.ScriptsLayout.setSpacing(0)
        self.ScriptsLayout.setAlignment(Qt.AlignTop)

        self.ScriptsArea.setWidget(self.ScriptsContents)

        self.ScriptsWidget.addWidget(self.ScriptsArea)

        self.SidebarLayout.addLayout(self.ScriptsWidget)

        self.ScriptsSpacer = QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.SidebarLayout.addItem(self.ScriptsSpacer)

        self.FiltersWidget = QVBoxLayout()
        self.FiltersWidget.setSpacing(0)
        self.FiltersWidget.setObjectName(u"FiltersWidget")
        self.FiltersHeader = QPushButton(PluginDialog)
        self.FiltersHeader.setObjectName(u"FiltersHeader")
        self.FiltersHeader.setMinimumSize(QSize(0, 30))
        self.FiltersHeader.setProperty('class', 'head')
        font1 = QFont()
        font1.setBold(True)
        font1.setWeight(75)
        self.FiltersHeader.setFont(font1)
        self.FiltersHeader.setCursor(QCursor(Qt.PointingHandCursor))

        self.FiltersWidget.addWidget(self.FiltersHeader)

        self.FiltersGroup = QGroupBox(PluginDialog)
        self.FiltersGroup.setObjectName(u"FiltersGroup")
        self.FiltersGroup.setMinimumSize(QSize(0, 100))
        self.FiltersGroup.setAlignment(Qt.AlignBottom|Qt.AlignLeading|Qt.AlignLeft)
        self.FiltersAdapter = QVBoxLayout(self.FiltersGroup)
        self.FiltersAdapter.setObjectName(u"FiltersAdapter")


        self.FilterSpacerBeg = QSpacerItem(20, 12, QSizePolicy.Minimum, QSizePolicy.Fixed)
        self.FiltersAdapter.addItem(self.FilterSpacerBeg)

        self.FolderFilter = QHBoxLayout()
        self.FolderFilter.setSpacing(0)
        self.FolderFilter.setObjectName(u"FolderFilter")
        self.FfSpacerBeg = QSpacerItem(14, 26, QSizePolicy.Fixed, QSizePolicy.Minimum)
        self.FolderFilter.addItem(self.FfSpacerBeg)

        self.FolderHeader = QPushButton(self.FiltersGroup)
        self.FolderHeader.setObjectName(u"FolderHeader")
        self.FolderHeader.setFont(font1)
        self.FolderHeader.setMinimumSize(QSize(96, 26))
        self.FolderHeader.setMaximumSize(QSize(96, 26))
        self.FolderHeader.setProperty('class', 'select-head')

        self.FolderFilter.addWidget(self.FolderHeader)

        self.FolderSelect = CheckableComboBox()  # QComboBox(self.FiltersGroup)
        self.FolderSelect.setObjectName(u"FolderSelect")
        self.FolderSelect.setMinimumSize(QSize(16777215, 26))
        self.FolderSelect.setMaximumSize(QSize(16777215, 26))
        self.FolderSelect.lineEdit().setPlaceholderText("Select filters...")
        self.FolderFilter.addWidget(self.FolderSelect)

        self.FfSpacerEnd = QSpacerItem(14, 26, QSizePolicy.Fixed, QSizePolicy.Minimum)
        self.FolderFilter.addItem(self.FfSpacerEnd)

        self.FolderFilter.setStretch(0, 0)
        self.FolderFilter.setStretch(1, 5)
        self.FolderFilter.setStretch(2, 7)
        self.FolderFilter.setStretch(3, 0)
        self.FiltersAdapter.addLayout(self.FolderFilter)

        self.FolderFilterSpacer = QSpacerItem(20, 12, QSizePolicy.Minimum, QSizePolicy.Fixed)
        self.FiltersAdapter.addItem(self.FolderFilterSpacer)

        self.PrefixFilter = QHBoxLayout()
        self.PrefixFilter.setSpacing(0)
        self.PrefixFilter.setObjectName(u"PrefixFilter")
        self.PfSpacerBeg = QSpacerItem(14, 26, QSizePolicy.Fixed, QSizePolicy.Minimum)
        self.PrefixFilter.addItem(self.PfSpacerBeg)

        self.PrefixHeader = QPushButton(self.FiltersGroup)
        self.PrefixHeader.setObjectName(u"PrefixHeader")
        self.PrefixHeader.setFont(font1)
        self.PrefixHeader.setMinimumSize(QSize(96, 26))
        self.PrefixHeader.setMaximumSize(QSize(96, 26))
        self.PrefixHeader.setProperty('class', 'select-head')

        self.PrefixFilter.addWidget(self.PrefixHeader)

        self.PrefixSelect = CheckableComboBox()  # QComboBox(self.FiltersGroup)
        self.PrefixSelect.setObjectName(u"PrefixSelect")
        self.PrefixSelect.setEnabled(True)
        self.PrefixSelect.setAutoFillBackground(False)
        self.PrefixSelect.setMinimumSize(QSize(16777215, 26))
        self.PrefixSelect.setMaximumSize(QSize(16777215, 26))
        self.PrefixSelect.lineEdit().setPlaceholderText("Select filters...")
        # self.PrefixSelect.setEditable(True)

        self.PrefixFilter.addWidget(self.PrefixSelect)
        self.PfSpacerEnd = QSpacerItem(14, 26, QSizePolicy.Fixed, QSizePolicy.Minimum)
        self.PrefixFilter.addItem(self.PfSpacerEnd)

        self.PrefixFilter.setStretch(0, 0)
        self.PrefixFilter.setStretch(1, 5)
        self.PrefixFilter.setStretch(2, 7)
        self.PrefixFilter.setStretch(3, 0)
        self.FiltersAdapter.addLayout(self.PrefixFilter)

        self.PrefixFilterSpacer = QSpacerItem(20, 12, QSizePolicy.Minimum, QSizePolicy.Fixed)
        self.FiltersAdapter.addItem(self.PrefixFilterSpacer)

        self.ColorFilter = QHBoxLayout()
        self.ColorFilter.setObjectName(u"ColorFilter")

        self.CfSpacerBeg = QSpacerItem(40, 26, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ColorFilter.addItem(self.CfSpacerBeg)

        self.PaletteYellow = QPushButton(self.FiltersGroup)
        self.PaletteYellow.setObjectName(u"PaletteYellow")
        self.PaletteYellow.setMinimumSize(QSize(26, 26))
        self.PaletteYellow.setMaximumSize(QSize(26, 26))
        self.PaletteYellow.setCheckable(True)
        self.PaletteYellow.setCursor(QCursor(Qt.PointingHandCursor))

        self.ColorFilter.addWidget(self.PaletteYellow)

        self.PaletteBlue = QPushButton(self.FiltersGroup)
        self.PaletteBlue.setObjectName(u"PaletteBlue")
        self.PaletteBlue.setMinimumSize(QSize(26, 26))
        self.PaletteBlue.setMaximumSize(QSize(26, 26))
        self.PaletteBlue.setCheckable(True)
        self.PaletteBlue.setCursor(QCursor(Qt.PointingHandCursor))

        self.ColorFilter.addWidget(self.PaletteBlue)

        self.PaletteGreen = QPushButton(self.FiltersGroup)
        self.PaletteGreen.setObjectName(u"PaletteGreen")
        self.PaletteGreen.setMinimumSize(QSize(26, 26))
        self.PaletteGreen.setMaximumSize(QSize(26, 26))
        self.PaletteGreen.setCheckable(True)
        self.PaletteGreen.setCursor(QCursor(Qt.PointingHandCursor))

        self.ColorFilter.addWidget(self.PaletteGreen)

        self.PalettePink = QPushButton(self.FiltersGroup)
        self.PalettePink.setObjectName(u"PalettePink")
        self.PalettePink.setMinimumSize(QSize(26, 26))
        self.PalettePink.setMaximumSize(QSize(26, 26))
        self.PalettePink.setCheckable(True)
        self.PalettePink.setCursor(QCursor(Qt.PointingHandCursor))

        self.ColorFilter.addWidget(self.PalettePink)

        self.PaletteNone = QPushButton(self.FiltersGroup)
        self.PaletteNone.setObjectName(u"PaletteNone")
        self.PaletteNone.setMinimumSize(QSize(26, 26))
        self.PaletteNone.setMaximumSize(QSize(26, 26))
        self.PaletteNone.setCheckable(True)
        self.PaletteNone.setCursor(QCursor(Qt.PointingHandCursor))

        self.ColorFilter.addWidget(self.PaletteNone)


        self.CfSpacerEnd = QSpacerItem(40, 26, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ColorFilter.addItem(self.CfSpacerEnd)

        self.FiltersAdapter.addLayout(self.ColorFilter)

        self.FilterSpacerEnd = QSpacerItem(20, 12, QSizePolicy.Minimum, QSizePolicy.Fixed)
        self.FiltersAdapter.addItem(self.FilterSpacerEnd)

        self.FiltersWidget.addWidget(self.FiltersGroup)

        self.SidebarLayout.addLayout(self.FiltersWidget)

        self.FiltersSpacer = QSpacerItem(20, 14, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.SidebarLayout.addItem(self.FiltersSpacer)


        self.splitter.addWidget(self.SidebarFrame)
        self.splitter.setStretchFactor(1,3)

        self.ContentFrame = QFrame(PluginDialog)
        self.ContentLayout = QVBoxLayout(self.ContentFrame)
        self.ContentLayout.setSpacing(0)
        self.ContentLayout.setObjectName(u"ContentLayout")
        self.ContentLayout.setContentsMargins(0, 0, 5, 0)

        self.progressBar = QProgressBar(PluginDialog)
        self.progressBar.setObjectName(u"progressBar")
        self.progressBar.setMinimumSize(QSize(0, 5))
        self.progressBar.setMaximumSize(QSize(16777215, 5))
        self.progressBar.setValue(24)
        self.progressBar.setTextVisible(False)
        self.progressBar.setVisible(False)

        self.worker = Worker()
        self.worker.updateProgress.connect(self.setProgress)

        self.ContentLayout.addWidget(self.progressBar)

        self.ResultsLayout = QHBoxLayout()
        self.ResultsLayout.setObjectName(u"ResultsLayout")
        self.ResultsView = QTreeView(PluginDialog)
        self.ResultsView.setObjectName(u"ResultsView")
        self.ResultsView.setAlternatingRowColors(True)
        self.ResultsView.header().setDefaultAlignment(Qt.AlignHCenter)
        self.ResultsView.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.ResultsView.setEditTriggers(QTreeView.NoEditTriggers)
        self.ResultsView.setContextMenuPolicy(Qt.CustomContextMenu)

        self.ResultsLayout.addWidget(self.ResultsView)

        self.ContentLayout.addLayout(self.ResultsLayout)

        self.ResultsSpacer = QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.ContentLayout.addItem(self.ResultsSpacer)

        self.ToolsWidget = QHBoxLayout()
        self.ToolsWidget.setSpacing(6)
        self.ToolsWidget.setObjectName(u"ToolsWidget")
        self.BegSpacer = QSpacerItem(10, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.ToolsWidget.addItem(self.BegSpacer)

        self.NameTool = QHBoxLayout()
        self.NameTool.setObjectName(u"NameTool")
        self.ModeToggle = QPushButton(PluginDialog)
        self.ModeToggle.setObjectName(u"ModeToggle")
        self.ModeToggle.setMinimumSize(QSize(30, 30))
        self.ModeToggle.setMaximumSize(QSize(30, 30))
        self.ModeToggle.setFont(font)
        self.ModeToggle.setCheckable(True)
        self.ModeToggle.setCursor(QCursor(Qt.PointingHandCursor))
        self.NameTool.addWidget(self.ModeToggle)

        self.NameComp = QHBoxLayout()
        self.NameComp.setSpacing(0)
        self.NameComp.setObjectName(u"NameComp")
        self.NameToggle = QPushButton(PluginDialog)
        self.NameToggle.setObjectName(u"NameToggle")
        self.NameToggle.setCursor(QCursor(Qt.PointingHandCursor))

        self.NameToggle.setMinimumSize(QSize(75, 30))
        self.NameToggle.setMaximumSize(QSize(75, 30))
        self.NameToggle.setFont(font)
        self.NameToggle.setCheckable(False)
        self.NameToggle.setAutoExclusive(False)

        self.NameComp.addWidget(self.NameToggle)

        self.NameEdit = QLineEdit(PluginDialog)
        self.NameEdit.setObjectName(u"NameEdit")
        self.NameEdit.setMaximumSize(QSize(16777215, 30))
        self.NameEdit.setPlaceholderText("Insert prefix")

        self.NameComp.addWidget(self.NameEdit)

        self.NameComp.setStretch(0, 2)
        self.NameComp.setStretch(1, 5)

        self.NameTool.addLayout(self.NameComp)

        self.SetNameButton = QPushButton(PluginDialog)
        self.SetNameButton.setObjectName(u"SetNameButton")
        self.SetNameButton.setMinimumSize(QSize(75, 30))
        self.SetNameButton.setMaximumSize(QSize(75, 30))
        self.SetNameButton.setFont(font)
        self.SetNameButton.setEnabled(False)
        self.SetNameButton.setCursor(QCursor(Qt.PointingHandCursor))

        self.NameTool.addWidget(self.SetNameButton)

        self.ClsNameButton = QPushButton(PluginDialog)
        self.ClsNameButton.setObjectName(u"ClsNameButton")
        self.ClsNameButton.setMinimumSize(QSize(75, 30))
        self.ClsNameButton.setMaximumSize(QSize(75, 30))
        self.ClsNameButton.setFont(font)
        self.ClsNameButton.setEnabled(False)
        self.ClsNameButton.setCursor(QCursor(Qt.PointingHandCursor))

        self.NameTool.addWidget(self.ClsNameButton)


        self.ToolsWidget.addLayout(self.NameTool)

        self.MidSpacer = QSpacerItem(160, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.ToolsWidget.addItem(self.MidSpacer)

        self.PaletteTool = QHBoxLayout()
        self.PaletteTool.setObjectName(u"PaletteTool")

        self.SetColorYellow = QPushButton(PluginDialog)
        self.SetColorYellow.setObjectName(u"SetColorYellow")
        self.SetColorYellow.setMinimumSize(QSize(30, 30))
        self.SetColorYellow.setMaximumSize(QSize(30, 30))
        self.SetColorYellow.setCheckable(True)
        self.SetColorYellow.setChecked(False)
        self.SetColorYellow.setAutoExclusive(True)
        self.SetColorYellow.setEnabled(False)
        self.SetColorYellow.setCursor(QCursor(Qt.PointingHandCursor))

        self.PaletteTool.addWidget(self.SetColorYellow)

        self.SetColorBlue = QPushButton(PluginDialog)
        self.SetColorBlue.setObjectName(u"SetColorBlue")
        self.SetColorBlue.setMinimumSize(QSize(30, 30))
        self.SetColorBlue.setMaximumSize(QSize(30, 30))
        self.SetColorBlue.setCheckable(True)
        self.SetColorBlue.setAutoExclusive(True)
        self.SetColorBlue.setEnabled(False)
        self.SetColorBlue.setCursor(QCursor(Qt.PointingHandCursor))

        self.PaletteTool.addWidget(self.SetColorBlue)

        self.SetColorGreen = QPushButton(PluginDialog)
        self.SetColorGreen.setObjectName(u"SetColorGreen")
        self.SetColorGreen.setMinimumSize(QSize(30, 30))
        self.SetColorGreen.setMaximumSize(QSize(30, 30))
        self.SetColorGreen.setCheckable(True)
        self.SetColorGreen.setAutoExclusive(True)
        self.SetColorGreen.setEnabled(False)
        self.SetColorGreen.setCursor(QCursor(Qt.PointingHandCursor))

        self.PaletteTool.addWidget(self.SetColorGreen)

        self.SetColorPink = QPushButton(PluginDialog)
        self.SetColorPink.setObjectName(u"SetColorPink")
        self.SetColorPink.setMinimumSize(QSize(30, 30))
        self.SetColorPink.setMaximumSize(QSize(30, 30))
        self.SetColorPink.setCheckable(True)
        self.SetColorPink.setAutoExclusive(True)
        self.SetColorPink.setEnabled(False)
        self.SetColorPink.setCursor(QCursor(Qt.PointingHandCursor))

        self.PaletteTool.addWidget(self.SetColorPink)

        self.SetColorNone = QPushButton(PluginDialog)
        self.SetColorNone.setObjectName(u"SetColorNone")
        self.SetColorNone.setMinimumSize(QSize(30, 30))
        self.SetColorNone.setMaximumSize(QSize(30, 30))
        self.SetColorNone.setCheckable(True)
        self.SetColorNone.setAutoExclusive(True)
        self.SetColorNone.setEnabled(False)
        self.SetColorNone.setCursor(QCursor(Qt.PointingHandCursor))

        self.PaletteTool.addWidget(self.SetColorNone)

        self.ToolsWidget.addLayout(self.PaletteTool)

        self.EndSpacer = QSpacerItem(10, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.ToolsWidget.addItem(self.EndSpacer)

        self.ContentLayout.addLayout(self.ToolsWidget)

        self.ToolsSpacer = QSpacerItem(20, 14, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.ContentLayout.addItem(self.ToolsSpacer)

        self.ContentLayout.setStretch(0, 8)
        self.ContentLayout.setStretch(1, 1)
        self.ContentLayout.setStretch(3, 1)

        self.splitter.addWidget(self.ContentFrame)

        self.MainLayout.setStretch(0, 3)
        self.MainLayout.setStretch(1, 9)

        self.splitter.setCollapsible(0,False)
        self.splitter.setCollapsible(1,False)
        self.MainLayout.addWidget(self.splitter)
        self.PluginAdapter.addLayout(self.MainLayout)


        self.retranslateUi(PluginDialog)

        QMetaObject.connectSlotsByName(PluginDialog)
    # setupUi

    def retranslateUi(self, PluginDialog):
        PluginDialog.setWindowTitle(i18n("Dialog"))
        self.ScriptsHeader.setText(i18n("TOOLKIT"))
        self.FiltersHeader.setText(i18n("FILTERS"))
        self.FiltersGroup.setTitle("")
        self.PrefixHeader.setText(i18n("PREFIXES"))
        # self.PrefixSelect.setCurrentText("")
        # self.PrefixSelect.setPlaceholderText(i18n("-"))
        # self.FolderSelect.setPlaceholderText(i18n("-"))
        self.FolderHeader.setText(i18n("FOLDERS"))
        self.PaletteYellow.setText("")
        self.PaletteBlue.setText("")
        self.PaletteGreen.setText("")
        self.PalettePink.setText("")
        self.ModeToggle.setText(i18n("R"))
        self.ModeToggle.setToolTip(i18n("Toggle recursive mode on/off"))
        self.NameToggle.setToolTip(i18n("Switch between Prefix and Folder modes"))
        self.NameToggle.setText(i18n("PREFIX"))
        self.SetNameButton.setText(i18n("ADD"))
        self.ClsNameButton.setText(i18n("CLEAR"))

        self.SetColorYellow.setToolTip(i18n("Highlight function yellow"))
        self.SetColorBlue.setToolTip(i18n("Highlight function blue"))
        self.SetColorGreen.setToolTip(i18n("Highlight function green"))
        self.SetColorPink.setToolTip(i18n("Highlight function pink"))
        self.SetColorNone.setToolTip(i18n("Remove function highlight"))

        self.SetColorYellow.setText("")
        self.SetColorBlue.setText("")
        self.SetColorGreen.setText("")
        self.SetColorPink.setText("")
        self.SetColorNone.setText("")
    # retranslateUi

    def setProgress(self, progress):
        if progress == 0:
            self.progressBar.setVisible(False)
        elif progress == 100:
            self.progressBar.setVisible(False)
            self.progressBar.setValue(0)
        else:
            self.progressBar.setVisible(True)
            self.progressBar.setValue(progress)
