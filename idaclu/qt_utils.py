# Based on original idea and PoC by Caroline 'By0ute' Beyne
# https://github.com/By0ute/pyqt-collapsible-widget

from idaclu.qt_shims import (
    QCoreApplication,
)


def i18n(text, context="PluginDialog"):
    return QCoreApplication.translate(context, text)
