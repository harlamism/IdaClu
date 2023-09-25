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
from idaclu import qt_shims

class Worker(qt_shims.get_QThread()):
    updateProgress = qt_shims.get_Signal()(int)

    def __init__(self):
        qt_shims.get_QThread().__init__(self)

    def run(self):
        for i in range(1, 101):
            self.updateProgress.emit(i)
            time.sleep(0.01)

class CheckableComboBox(qt_shims.get_QComboBox()):
    def __init__(self):
        super(CheckableComboBox, self).__init__()
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        self.closeOnLineEditClick = False
        self.lineEdit().installEventFilter(self)
        self.view().viewport().installEventFilter(self)
        self.model().dataChanged.connect(self.updateLineEditField)
        self.itemDelegate = qt_shims.get_QStyledItemDelegate()(self)
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
        item = qt_shims.get_QStandardItem()()
        item.setText(text)
        if not userData is None:
            item.setData(userData)
        item.setFlags(qt_shims.get_Qt().ItemIsEnabled | qt_shims.get_Qt().ItemIsUserCheckable)
        item.setData(qt_shims.get_Qt().Unchecked, qt_shims.get_Qt().CheckStateRole)
        self.model().appendRow(item)

    def eventFilter(self, widget, event):
        if widget == self.lineEdit():
            if event.type() == qt_shims.get_QEvent().MouseButtonRelease:
                if self.closeOnLineEditClick:
                    self.hidePopup()
                else:
                    self.showPopup()
                return True
            return super(CheckableComboBox, self).eventFilter(widget, event)
        if widget == self.view().viewport():
            if event.type() == qt_shims.get_QEvent().MouseButtonRelease:
                indx = self.view().indexAt(event.pos())
                item = self.model().item(indx.row())

                if item.checkState() == qt_shims.get_Qt().Checked:
                    item.setCheckState(qt_shims.get_Qt().Unchecked)
                else:
                    item.setCheckState(qt_shims.get_Qt().Checked)
                return True
            return super(CheckableComboBox, self).eventFilter(widget, event)

    def updateLineEditField(self):
        text_container = []
        for i in range(self.model().rowCount()):
            if self.model().item(i).checkState() == qt_shims.get_Qt().Checked:
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

        icon = qt_shims.get_QIcon()()
        icon.addFile(":/idaclu/icon_64.png", qt_shims.get_QSize()(), qt_shims.get_QIcon().Normal, qt_shims.get_QIcon().Off)
        PluginDialog.setWindowIcon(icon)

        self.PluginAdapter = qt_shims.get_QHBoxLayout()(PluginDialog)
        self.PluginAdapter.setObjectName(u"PluginAdapter")

        self.splitter = qt_shims.get_QSplitter()()
        self.splitter.setOrientation(qt_shims.get_Qt().Horizontal)
        self.splitter.setObjectName("splitter")

        self.MainLayout = qt_shims.get_QHBoxLayout()()
        self.MainLayout.setObjectName(u"MainLayout")

        self.SidebarFrame = qt_shims.get_QFrame()(PluginDialog)
        self.SidebarLayout = qt_shims.get_QVBoxLayout()(self.SidebarFrame)
        self.SidebarLayout.setSpacing(0)
        self.SidebarLayout.setObjectName(u"SidebarLayout")
        self.SidebarLayout.setContentsMargins(0, 0, 5, 0)

        self.ScriptsWidget = qt_shims.get_QVBoxLayout()()
        self.ScriptsWidget.setSpacing(0)
        self.ScriptsWidget.setObjectName(u"ScriptsWidget")
        self.ScriptsHeader = qt_shims.get_QPushButton()(PluginDialog)
        self.ScriptsHeader.setObjectName(u"ScriptsHeader")
        self.ScriptsHeader.setMinimumSize(qt_shims.get_QSize()(0, 30))
        font = qt_shims.get_QFont()()
        font.setBold(True)
        font.setWeight(75)
        self.ScriptsHeader.setFont(font)
        self.ScriptsHeader.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))
        self.ScriptsHeader.setProperty('class', 'head')
        self.ScriptsWidget.addWidget(self.ScriptsHeader)

        self.ScriptsArea = qt_shims.get_QScrollArea()(PluginDialog)
        self.ScriptsArea.setObjectName(u"ScriptsArea")
        self.ScriptsArea.setWidgetResizable(True)
        self.ScriptsArea.horizontalScrollBar().setEnabled(False)
        self.ScriptsArea.setHorizontalScrollBarPolicy(qt_shims.get_Qt().ScrollBarAlwaysOff)

        self.ScriptsContents = qt_shims.get_QWidget()()
        self.ScriptsContents.setObjectName(u"ScriptsContents")
        self.ScriptsContents.setGeometry(qt_shims.get_QRect()(0, 0, 215, 233))

        # custom
        # sub-plugin script buttons are added to the scrollable layout
        self.ScriptsLayout = qt_shims.get_QVBoxLayout()(self.ScriptsContents)
        self.ScriptsLayout.setSpacing(0)
        self.ScriptsLayout.setAlignment(qt_shims.get_Qt().AlignTop)

        self.ScriptsArea.setWidget(self.ScriptsContents)

        self.ScriptsWidget.addWidget(self.ScriptsArea)

        self.SidebarLayout.addLayout(self.ScriptsWidget)

        self.ScriptsSpacer = qt_shims.get_QSpacerItem()(20, 10, qt_shims.get_QSizePolicy().Minimum, qt_shims.get_QSizePolicy().Fixed)

        self.SidebarLayout.addItem(self.ScriptsSpacer)

        self.FiltersWidget = qt_shims.get_QVBoxLayout()()
        self.FiltersWidget.setSpacing(0)
        self.FiltersWidget.setObjectName(u"FiltersWidget")
        self.FiltersHeader = qt_shims.get_QPushButton()(PluginDialog)
        self.FiltersHeader.setObjectName(u"FiltersHeader")
        self.FiltersHeader.setMinimumSize(qt_shims.get_QSize()(0, 30))
        self.FiltersHeader.setProperty('class', 'head')
        font1 = qt_shims.get_QFont()()
        font1.setBold(True)
        font1.setWeight(75)
        self.FiltersHeader.setFont(font1)
        self.FiltersHeader.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.FiltersWidget.addWidget(self.FiltersHeader)

        self.FiltersGroup = qt_shims.get_QGroupBox()(PluginDialog)
        self.FiltersGroup.setObjectName(u"FiltersGroup")
        self.FiltersGroup.setMinimumSize(qt_shims.get_QSize()(0, 100))
        self.FiltersGroup.setAlignment(qt_shims.get_Qt().AlignBottom|qt_shims.get_Qt().AlignLeading|qt_shims.get_Qt().AlignLeft)
        self.FiltersAdapter = qt_shims.get_QVBoxLayout()(self.FiltersGroup)
        self.FiltersAdapter.setObjectName(u"FiltersAdapter")


        self.FilterSpacerBeg = qt_shims.get_QSpacerItem()(20, 12, qt_shims.get_QSizePolicy().Minimum, qt_shims.get_QSizePolicy().Fixed)
        self.FiltersAdapter.addItem(self.FilterSpacerBeg)

        self.FolderFilter = qt_shims.get_QHBoxLayout()()
        self.FolderFilter.setSpacing(0)
        self.FolderFilter.setObjectName(u"FolderFilter")
        self.FfSpacerBeg = qt_shims.get_QSpacerItem()(14, 26, qt_shims.get_QSizePolicy().Fixed, qt_shims.get_QSizePolicy().Minimum)
        self.FolderFilter.addItem(self.FfSpacerBeg)

        self.FolderHeader = qt_shims.get_QPushButton()(self.FiltersGroup)
        self.FolderHeader.setObjectName(u"FolderHeader")
        self.FolderHeader.setFont(font1)
        self.FolderHeader.setMinimumSize(qt_shims.get_QSize()(96, 26))
        self.FolderHeader.setMaximumSize(qt_shims.get_QSize()(96, 26))
        self.FolderHeader.setProperty('class', 'select-head')

        self.FolderFilter.addWidget(self.FolderHeader)

        self.FolderSelect = CheckableComboBox()  # qt_shims.get_QComboBox()(self.FiltersGroup)
        self.FolderSelect.setObjectName(u"FolderSelect")
        self.FolderSelect.setMinimumSize(qt_shims.get_QSize()(16777215, 26))
        self.FolderSelect.setMaximumSize(qt_shims.get_QSize()(16777215, 26))
        self.FolderSelect.lineEdit().setPlaceholderText("Select filters...")
        self.FolderFilter.addWidget(self.FolderSelect)

        self.FfSpacerEnd = qt_shims.get_QSpacerItem()(14, 26, qt_shims.get_QSizePolicy().Fixed, qt_shims.get_QSizePolicy().Minimum)
        self.FolderFilter.addItem(self.FfSpacerEnd)

        self.FolderFilter.setStretch(0, 0)
        self.FolderFilter.setStretch(1, 5)
        self.FolderFilter.setStretch(2, 7)
        self.FolderFilter.setStretch(3, 0)
        self.FiltersAdapter.addLayout(self.FolderFilter)

        self.FolderFilterSpacer = qt_shims.get_QSpacerItem()(20, 12, qt_shims.get_QSizePolicy().Minimum, qt_shims.get_QSizePolicy().Fixed)
        self.FiltersAdapter.addItem(self.FolderFilterSpacer)

        self.PrefixFilter = qt_shims.get_QHBoxLayout()()
        self.PrefixFilter.setSpacing(0)
        self.PrefixFilter.setObjectName(u"PrefixFilter")
        self.PfSpacerBeg = qt_shims.get_QSpacerItem()(14, 26, qt_shims.get_QSizePolicy().Fixed, qt_shims.get_QSizePolicy().Minimum)
        self.PrefixFilter.addItem(self.PfSpacerBeg)

        self.PrefixHeader = qt_shims.get_QPushButton()(self.FiltersGroup)
        self.PrefixHeader.setObjectName(u"PrefixHeader")
        self.PrefixHeader.setFont(font1)
        self.PrefixHeader.setMinimumSize(qt_shims.get_QSize()(96, 26))
        self.PrefixHeader.setMaximumSize(qt_shims.get_QSize()(96, 26))
        self.PrefixHeader.setProperty('class', 'select-head')

        self.PrefixFilter.addWidget(self.PrefixHeader)

        self.PrefixSelect = CheckableComboBox()  # qt_shims.get_QComboBox()(self.FiltersGroup)
        self.PrefixSelect.setObjectName(u"PrefixSelect")
        self.PrefixSelect.setEnabled(True)
        self.PrefixSelect.setAutoFillBackground(False)
        self.PrefixSelect.setMinimumSize(qt_shims.get_QSize()(16777215, 26))
        self.PrefixSelect.setMaximumSize(qt_shims.get_QSize()(16777215, 26))
        self.PrefixSelect.lineEdit().setPlaceholderText("Select filters...")
        # self.PrefixSelect.setEditable(True)

        self.PrefixFilter.addWidget(self.PrefixSelect)
        self.PfSpacerEnd = qt_shims.get_QSpacerItem()(14, 26, qt_shims.get_QSizePolicy().Fixed, qt_shims.get_QSizePolicy().Minimum)
        self.PrefixFilter.addItem(self.PfSpacerEnd)

        self.PrefixFilter.setStretch(0, 0)
        self.PrefixFilter.setStretch(1, 5)
        self.PrefixFilter.setStretch(2, 7)
        self.PrefixFilter.setStretch(3, 0)
        self.FiltersAdapter.addLayout(self.PrefixFilter)

        self.PrefixFilterSpacer = qt_shims.get_QSpacerItem()(20, 12, qt_shims.get_QSizePolicy().Minimum, qt_shims.get_QSizePolicy().Fixed)
        self.FiltersAdapter.addItem(self.PrefixFilterSpacer)

        self.ColorFilter = qt_shims.get_QHBoxLayout()()
        self.ColorFilter.setObjectName(u"ColorFilter")

        self.CfSpacerBeg = qt_shims.get_QSpacerItem()(40, 26, qt_shims.get_QSizePolicy().Expanding, qt_shims.get_QSizePolicy().Minimum)
        self.ColorFilter.addItem(self.CfSpacerBeg)

        self.PaletteYellow = qt_shims.get_QPushButton()(self.FiltersGroup)
        self.PaletteYellow.setObjectName(u"PaletteYellow")
        self.PaletteYellow.setMinimumSize(qt_shims.get_QSize()(26, 26))
        self.PaletteYellow.setMaximumSize(qt_shims.get_QSize()(26, 26))
        self.PaletteYellow.setCheckable(True)
        self.PaletteYellow.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.ColorFilter.addWidget(self.PaletteYellow)

        self.PaletteBlue = qt_shims.get_QPushButton()(self.FiltersGroup)
        self.PaletteBlue.setObjectName(u"PaletteBlue")
        self.PaletteBlue.setMinimumSize(qt_shims.get_QSize()(26, 26))
        self.PaletteBlue.setMaximumSize(qt_shims.get_QSize()(26, 26))
        self.PaletteBlue.setCheckable(True)
        self.PaletteBlue.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.ColorFilter.addWidget(self.PaletteBlue)

        self.PaletteGreen = qt_shims.get_QPushButton()(self.FiltersGroup)
        self.PaletteGreen.setObjectName(u"PaletteGreen")
        self.PaletteGreen.setMinimumSize(qt_shims.get_QSize()(26, 26))
        self.PaletteGreen.setMaximumSize(qt_shims.get_QSize()(26, 26))
        self.PaletteGreen.setCheckable(True)
        self.PaletteGreen.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.ColorFilter.addWidget(self.PaletteGreen)

        self.PalettePink = qt_shims.get_QPushButton()(self.FiltersGroup)
        self.PalettePink.setObjectName(u"PalettePink")
        self.PalettePink.setMinimumSize(qt_shims.get_QSize()(26, 26))
        self.PalettePink.setMaximumSize(qt_shims.get_QSize()(26, 26))
        self.PalettePink.setCheckable(True)
        self.PalettePink.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.ColorFilter.addWidget(self.PalettePink)

        self.PaletteNone = qt_shims.get_QPushButton()(self.FiltersGroup)
        self.PaletteNone.setObjectName(u"PaletteNone")
        self.PaletteNone.setMinimumSize(qt_shims.get_QSize()(26, 26))
        self.PaletteNone.setMaximumSize(qt_shims.get_QSize()(26, 26))
        self.PaletteNone.setCheckable(True)
        self.PaletteNone.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.ColorFilter.addWidget(self.PaletteNone)


        self.CfSpacerEnd = qt_shims.get_QSpacerItem()(40, 26, qt_shims.get_QSizePolicy().Expanding, qt_shims.get_QSizePolicy().Minimum)
        self.ColorFilter.addItem(self.CfSpacerEnd)

        self.FiltersAdapter.addLayout(self.ColorFilter)

        self.FilterSpacerEnd = qt_shims.get_QSpacerItem()(20, 12, qt_shims.get_QSizePolicy().Minimum, qt_shims.get_QSizePolicy().Fixed)
        self.FiltersAdapter.addItem(self.FilterSpacerEnd)

        self.FiltersWidget.addWidget(self.FiltersGroup)

        self.SidebarLayout.addLayout(self.FiltersWidget)

        self.FiltersSpacer = qt_shims.get_QSpacerItem()(20, 14, qt_shims.get_QSizePolicy().Minimum, qt_shims.get_QSizePolicy().Fixed)

        self.SidebarLayout.addItem(self.FiltersSpacer)


        self.splitter.addWidget(self.SidebarFrame)
        self.splitter.setStretchFactor(1,3)

        self.ContentFrame = qt_shims.get_QFrame()(PluginDialog)
        self.ContentLayout = qt_shims.get_QVBoxLayout()(self.ContentFrame)
        self.ContentLayout.setSpacing(0)
        self.ContentLayout.setObjectName(u"ContentLayout")
        self.ContentLayout.setContentsMargins(0, 0, 5, 0)

        self.progressBar = qt_shims.get_QProgressBar()(PluginDialog)
        self.progressBar.setObjectName(u"progressBar")
        self.progressBar.setMinimumSize(qt_shims.get_QSize()(0, 5))
        self.progressBar.setMaximumSize(qt_shims.get_QSize()(16777215, 5))
        self.progressBar.setValue(24)
        self.progressBar.setTextVisible(False)
        self.progressBar.setVisible(False)

        self.worker = Worker()
        self.worker.updateProgress.connect(self.setProgress)

        self.ContentLayout.addWidget(self.progressBar)

        self.ResultsLayout = qt_shims.get_QHBoxLayout()()
        self.ResultsLayout.setObjectName(u"ResultsLayout")
        self.ResultsView = qt_shims.get_QTreeView()(PluginDialog)
        self.ResultsView.setObjectName(u"ResultsView")
        self.ResultsView.setAlternatingRowColors(True)
        self.ResultsView.header().setDefaultAlignment(qt_shims.get_Qt().AlignHCenter)
        self.ResultsView.setSelectionMode(qt_shims.get_QAbstractItemView().ExtendedSelection)
        self.ResultsView.setEditTriggers(qt_shims.get_QTreeView().NoEditTriggers)
        self.ResultsView.setContextMenuPolicy(qt_shims.get_Qt().CustomContextMenu)

        self.ResultsLayout.addWidget(self.ResultsView)

        self.ContentLayout.addLayout(self.ResultsLayout)

        self.ResultsSpacer = qt_shims.get_QSpacerItem()(20, 10, qt_shims.get_QSizePolicy().Minimum, qt_shims.get_QSizePolicy().Fixed)

        self.ContentLayout.addItem(self.ResultsSpacer)

        self.ToolsWidget = qt_shims.get_QHBoxLayout()()
        self.ToolsWidget.setSpacing(6)
        self.ToolsWidget.setObjectName(u"ToolsWidget")
        self.BegSpacer = qt_shims.get_QSpacerItem()(10, 20, qt_shims.get_QSizePolicy().Fixed, qt_shims.get_QSizePolicy().Minimum)

        self.ToolsWidget.addItem(self.BegSpacer)

        self.NameTool = qt_shims.get_QHBoxLayout()()
        self.NameTool.setObjectName(u"NameTool")
        self.ModeToggle = qt_shims.get_QPushButton()(PluginDialog)
        self.ModeToggle.setObjectName(u"ModeToggle")
        self.ModeToggle.setMinimumSize(qt_shims.get_QSize()(30, 30))
        self.ModeToggle.setMaximumSize(qt_shims.get_QSize()(30, 30))
        self.ModeToggle.setFont(font)
        self.ModeToggle.setCheckable(True)
        self.ModeToggle.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))
        self.NameTool.addWidget(self.ModeToggle)

        self.NameComp = qt_shims.get_QHBoxLayout()()
        self.NameComp.setSpacing(0)
        self.NameComp.setObjectName(u"NameComp")
        self.NameToggle = qt_shims.get_QPushButton()(PluginDialog)
        self.NameToggle.setObjectName(u"NameToggle")
        self.NameToggle.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.NameToggle.setMinimumSize(qt_shims.get_QSize()(75, 30))
        self.NameToggle.setMaximumSize(qt_shims.get_QSize()(75, 30))
        self.NameToggle.setFont(font)
        self.NameToggle.setCheckable(False)
        self.NameToggle.setAutoExclusive(False)

        self.NameComp.addWidget(self.NameToggle)

        self.NameEdit = qt_shims.get_QLineEdit()(PluginDialog)
        self.NameEdit.setObjectName(u"NameEdit")
        self.NameEdit.setMaximumSize(qt_shims.get_QSize()(16777215, 30))
        self.NameEdit.setPlaceholderText("Insert prefix")

        self.NameComp.addWidget(self.NameEdit)

        self.NameComp.setStretch(0, 2)
        self.NameComp.setStretch(1, 5)

        self.NameTool.addLayout(self.NameComp)

        self.SetNameButton = qt_shims.get_QPushButton()(PluginDialog)
        self.SetNameButton.setObjectName(u"SetNameButton")
        self.SetNameButton.setMinimumSize(qt_shims.get_QSize()(75, 30))
        self.SetNameButton.setMaximumSize(qt_shims.get_QSize()(75, 30))
        self.SetNameButton.setFont(font)
        self.SetNameButton.setEnabled(False)
        self.SetNameButton.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.NameTool.addWidget(self.SetNameButton)

        self.ClsNameButton = qt_shims.get_QPushButton()(PluginDialog)
        self.ClsNameButton.setObjectName(u"ClsNameButton")
        self.ClsNameButton.setMinimumSize(qt_shims.get_QSize()(75, 30))
        self.ClsNameButton.setMaximumSize(qt_shims.get_QSize()(75, 30))
        self.ClsNameButton.setFont(font)
        self.ClsNameButton.setEnabled(False)
        self.ClsNameButton.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.NameTool.addWidget(self.ClsNameButton)


        self.ToolsWidget.addLayout(self.NameTool)

        self.MidSpacer = qt_shims.get_QSpacerItem()(160, 20, qt_shims.get_QSizePolicy().Expanding, qt_shims.get_QSizePolicy().Minimum)

        self.ToolsWidget.addItem(self.MidSpacer)

        self.PaletteTool = qt_shims.get_QHBoxLayout()()
        self.PaletteTool.setObjectName(u"PaletteTool")

        self.SetColorYellow = qt_shims.get_QPushButton()(PluginDialog)
        self.SetColorYellow.setObjectName(u"SetColorYellow")
        self.SetColorYellow.setMinimumSize(qt_shims.get_QSize()(30, 30))
        self.SetColorYellow.setMaximumSize(qt_shims.get_QSize()(30, 30))
        self.SetColorYellow.setCheckable(True)
        self.SetColorYellow.setChecked(False)
        self.SetColorYellow.setAutoExclusive(True)
        self.SetColorYellow.setEnabled(False)
        self.SetColorYellow.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.PaletteTool.addWidget(self.SetColorYellow)

        self.SetColorBlue = qt_shims.get_QPushButton()(PluginDialog)
        self.SetColorBlue.setObjectName(u"SetColorBlue")
        self.SetColorBlue.setMinimumSize(qt_shims.get_QSize()(30, 30))
        self.SetColorBlue.setMaximumSize(qt_shims.get_QSize()(30, 30))
        self.SetColorBlue.setCheckable(True)
        self.SetColorBlue.setAutoExclusive(True)
        self.SetColorBlue.setEnabled(False)
        self.SetColorBlue.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.PaletteTool.addWidget(self.SetColorBlue)

        self.SetColorGreen = qt_shims.get_QPushButton()(PluginDialog)
        self.SetColorGreen.setObjectName(u"SetColorGreen")
        self.SetColorGreen.setMinimumSize(qt_shims.get_QSize()(30, 30))
        self.SetColorGreen.setMaximumSize(qt_shims.get_QSize()(30, 30))
        self.SetColorGreen.setCheckable(True)
        self.SetColorGreen.setAutoExclusive(True)
        self.SetColorGreen.setEnabled(False)
        self.SetColorGreen.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.PaletteTool.addWidget(self.SetColorGreen)

        self.SetColorPink = qt_shims.get_QPushButton()(PluginDialog)
        self.SetColorPink.setObjectName(u"SetColorPink")
        self.SetColorPink.setMinimumSize(qt_shims.get_QSize()(30, 30))
        self.SetColorPink.setMaximumSize(qt_shims.get_QSize()(30, 30))
        self.SetColorPink.setCheckable(True)
        self.SetColorPink.setAutoExclusive(True)
        self.SetColorPink.setEnabled(False)
        self.SetColorPink.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.PaletteTool.addWidget(self.SetColorPink)

        self.SetColorNone = qt_shims.get_QPushButton()(PluginDialog)
        self.SetColorNone.setObjectName(u"SetColorNone")
        self.SetColorNone.setMinimumSize(qt_shims.get_QSize()(30, 30))
        self.SetColorNone.setMaximumSize(qt_shims.get_QSize()(30, 30))
        self.SetColorNone.setCheckable(True)
        self.SetColorNone.setAutoExclusive(True)
        self.SetColorNone.setEnabled(False)
        self.SetColorNone.setCursor(qt_shims.get_QCursor()(qt_shims.get_Qt().PointingHandCursor))

        self.PaletteTool.addWidget(self.SetColorNone)

        self.ToolsWidget.addLayout(self.PaletteTool)

        self.EndSpacer = qt_shims.get_QSpacerItem()(10, 20, qt_shims.get_QSizePolicy().Fixed, qt_shims.get_QSizePolicy().Minimum)

        self.ToolsWidget.addItem(self.EndSpacer)

        self.ContentLayout.addLayout(self.ToolsWidget)

        self.ToolsSpacer = qt_shims.get_QSpacerItem()(20, 14, qt_shims.get_QSizePolicy().Minimum, qt_shims.get_QSizePolicy().Fixed)

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

        qt_shims.get_QMetaObject().connectSlotsByName(PluginDialog)
    # setupUi

    def retranslateUi(self, PluginDialog):
        _translate = qt_shims.get_QCoreApplication().translate
        PluginDialog.setWindowTitle(_translate("PluginDialog", "Dialog", None))
        self.ScriptsHeader.setText(_translate("PluginDialog", "TOOLKIT", None))
        self.FiltersHeader.setText(_translate("PluginDialog", "FILTERS", None))
        self.FiltersGroup.setTitle("")
        self.PrefixHeader.setText(_translate("PluginDialog", "PREFIXES", None))
        # self.PrefixSelect.setCurrentText("")
        # self.PrefixSelect.setPlaceholderText(_translate("PluginDialog", "-", None))
        # self.FolderSelect.setPlaceholderText(_translate("PluginDialog", "-", None))
        self.FolderHeader.setText(_translate("PluginDialog", "FOLDERS", None))
        self.PaletteYellow.setText("")
        self.PaletteBlue.setText("")
        self.PaletteGreen.setText("")
        self.PalettePink.setText("")
        self.ModeToggle.setText(_translate("PluginDialog", "R", None))
        self.ModeToggle.setToolTip(_translate("PluginDialog", "Toggle recursive mode on/off", None))
        self.NameToggle.setToolTip(_translate("PluginDialog", "Switch between Prefix and Folder modes", None))
        self.NameToggle.setText(_translate("PluginDialog", "PREFIX", None))
        self.SetNameButton.setText(_translate("PluginDialog", "ADD", None))
        self.ClsNameButton.setText(_translate("PluginDialog", "CLEAR", None))

        self.SetColorYellow.setToolTip(_translate("PluginDialog", "Highlight function yellow", None))
        self.SetColorBlue.setToolTip(_translate("PluginDialog", "Highlight function blue", None))
        self.SetColorGreen.setToolTip(_translate("PluginDialog", "Highlight function green", None))
        self.SetColorPink.setToolTip(_translate("PluginDialog", "Highlight function pink", None))
        self.SetColorNone.setToolTip(_translate("PluginDialog", "Remove function highlight", None))

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
