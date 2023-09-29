# Based on original idea and PoC by Caroline 'By0ute' Beyne
# https://github.com/By0ute/pyqt-collapsible-widget

from idaclu.qt_shims import (
    QColor,
    QCoreApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPainter,
    QPoint,
    QPointF,
    QVBoxLayout,
    QWidget,
    Signal
)


def i18n(text, context="PluginDialog"):
    return QCoreApplication.translate(context, text)

class FrameLayout(QWidget):
    def __init__(self, parent=None, title=None, env=None):
        self.env_desc = env
        QWidget.__init__(self, parent=parent)

        self._is_collasped = True
        self._title_frame = None
        self._content, self._content_layout = (None, None)

        title_frame = self.initTitleFrame(title, self._is_collasped)
        content_widget = self.initContent(self._is_collasped)

        self._main_v_layout = QVBoxLayout(self)
        self._main_v_layout.addWidget(title_frame)
        self._main_v_layout.addWidget(content_widget)

        self.initCollapsable()

    def initTitleFrame(self, title, collapsed):
        self._title_frame = self.TitleFrame(
            title=title,
            collapsed=collapsed,
            env=self.env_desc)
        return self._title_frame

    def initContent(self, collapsed):
        self._content = QWidget()
        self._content_layout = QVBoxLayout()

        self._content.setLayout(self._content_layout)
        self._content.setVisible(not collapsed)

        return self._content

    def addWidget(self, widget):
        self._content_layout.addWidget(widget)

    def initCollapsable(self):
        self._title_frame.clicked.connect(self.toggleCollapsed)

    def toggleCollapsed(self):
        self._content.setVisible(self._is_collasped)
        self._is_collasped = not self._is_collasped
        self._title_frame._arrow.setArrow(int(self._is_collasped))


    class TitleFrame(QFrame):

        clicked = Signal()
        def __init__(self, parent=None, title="", collapsed=False, env=None):
            QFrame.__init__(self, parent=parent)
            self.env_desc = env
            self.setMinimumHeight(24)
            self.move(QPoint(24, 0))

            self._hlayout = QHBoxLayout(self)
            self._hlayout.setContentsMargins(0, 0, 0, 0)
            self._hlayout.setSpacing(0)

            self._arrow = None
            self._title = None

            self._hlayout.addWidget(self.initArrow(collapsed))
            self._hlayout.addWidget(self.initTitle(title))

        def initArrow(self, collapsed):
            self._arrow = FrameLayout.Arrow(collapsed=collapsed, env=self.env_desc)
            return self._arrow

        def initTitle(self, title=None):
            self._title = QLabel(title)
            self._title.setMinimumHeight(24)
            self._title.move(QPoint(24, 0))

            return self._title

        def mousePressEvent(self, event):
            self.clicked.emit()
            return super(FrameLayout.TitleFrame, self).mousePressEvent(event)


    class Arrow(QFrame):
        def __init__(self, parent=None, collapsed=False, env=None):
            QFrame.__init__(self, parent=parent)
            self.env_desc = env
            self.setMaximumSize(24, 24)

            # horizontal == 0
            ha_point1 = QPointF(7.0, 8.0)
            ha_point2 = QPointF(17.0, 8.0)
            ha_point3 = QPointF(12.0, 13.0)
            self._arrow_horizontal = (ha_point1, ha_point2, ha_point3)
            # vertical == 1
            va_point1 = QPointF(8.0, 7.0)
            va_point2 = QPointF(13.0, 12.0)
            va_point3 = QPointF(8.0, 17.0)
            self._arrow_vertical = (va_point1, va_point2, va_point3)
            # arrow
            self._arrow = None
            self.setArrow(int(collapsed))

        def setArrow(self, arrow_dir):
            if arrow_dir:
                self._arrow = self._arrow_vertical
            else:
                self._arrow = self._arrow_horizontal

        def paintEvent(self, event):
            painter = QPainter()
            painter.begin(self)
            painter.setBrush(QColor(192, 192, 192))
            painter.setPen(QColor(64, 64, 64))
            if self.env_desc.lib_qt == 'pyqt5':
                painter.drawPolygon(*self._arrow)
            else:  # 'pyside'
                painter.drawPolygon(self._arrow)
            painter.end()
