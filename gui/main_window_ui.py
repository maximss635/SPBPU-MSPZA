# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main_window.ui'
#
# Created by: PyQt5 UI code generator 5.15.7
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1064, 652)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(10, 10, 1041, 601))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.layoutWidget = QtWidgets.QWidget(self.tab)
        self.layoutWidget.setGeometry(QtCore.QRect(0, 0, 1031, 551))
        self.layoutWidget.setObjectName("layoutWidget")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.layoutWidget)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.checkBox_pid = QtWidgets.QCheckBox(self.layoutWidget)
        self.checkBox_pid.setObjectName("checkBox_pid")
        self.horizontalLayout_4.addWidget(self.checkBox_pid)
        self.checkBox_exepath = QtWidgets.QCheckBox(self.layoutWidget)
        self.checkBox_exepath.setObjectName("checkBox_exepath")
        self.horizontalLayout_4.addWidget(self.checkBox_exepath)
        self.checkBox_netactiuvity = QtWidgets.QCheckBox(self.layoutWidget)
        self.checkBox_netactiuvity.setObjectName("checkBox_netactiuvity")
        self.horizontalLayout_4.addWidget(self.checkBox_netactiuvity)
        self.checkBox_sign = QtWidgets.QCheckBox(self.layoutWidget)
        self.checkBox_sign.setObjectName("checkBox_sign")
        self.horizontalLayout_4.addWidget(self.checkBox_sign)
        self.checkBox_packing = QtWidgets.QCheckBox(self.layoutWidget)
        self.checkBox_packing.setObjectName("checkBox_packing")
        self.horizontalLayout_4.addWidget(self.checkBox_packing)
        self.checkBox_sections = QtWidgets.QCheckBox(self.layoutWidget)
        self.checkBox_sections.setObjectName("checkBox_sections")
        self.horizontalLayout_4.addWidget(self.checkBox_sections)
        self.checkBox_capa = QtWidgets.QCheckBox(self.layoutWidget)
        self.checkBox_capa.setObjectName("checkBox_capa")
        self.horizontalLayout_4.addWidget(self.checkBox_capa)
        self.verticalLayout_3.addLayout(self.horizontalLayout_4)
        self.main_table = QtWidgets.QTableWidget(self.layoutWidget)
        self.main_table.setObjectName("main_table")
        self.main_table.setColumnCount(7)
        self.main_table.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.main_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.main_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.main_table.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.main_table.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.main_table.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.main_table.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.main_table.setHorizontalHeaderItem(6, item)
        self.verticalLayout_3.addWidget(self.main_table)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.button_start_scan = QtWidgets.QPushButton(self.layoutWidget)
        self.button_start_scan.setObjectName("button_start_scan")
        self.horizontalLayout_2.addWidget(self.button_start_scan)
        self.button_stop_scan = QtWidgets.QPushButton(self.layoutWidget)
        self.button_stop_scan.setObjectName("button_stop_scan")
        self.horizontalLayout_2.addWidget(self.button_stop_scan)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem)
        self.verticalLayout_3.addLayout(self.horizontalLayout_2)
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.layoutWidget_2 = QtWidgets.QWidget(self.tab_2)
        self.layoutWidget_2.setGeometry(QtCore.QRect(0, 0, 1031, 41))
        self.layoutWidget_2.setObjectName("layoutWidget_2")
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout(self.layoutWidget_2)
        self.horizontalLayout_8.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.textEdit_2 = QtWidgets.QTextEdit(self.layoutWidget_2)
        self.textEdit_2.setMaximumSize(QtCore.QSize(16777215, 30))
        self.textEdit_2.setObjectName("textEdit_2")
        self.horizontalLayout_8.addWidget(self.textEdit_2)
        self.button_capa_analyze_2 = QtWidgets.QPushButton(self.layoutWidget_2)
        self.button_capa_analyze_2.setObjectName("button_capa_analyze_2")
        self.horizontalLayout_8.addWidget(self.button_capa_analyze_2)
        self.table_codediff = QtWidgets.QTableWidget(self.tab_2)
        self.table_codediff.setGeometry(QtCore.QRect(0, 50, 1031, 501))
        self.table_codediff.setObjectName("table_codediff")
        self.table_codediff.setColumnCount(3)
        self.table_codediff.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.table_codediff.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_codediff.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_codediff.setHorizontalHeaderItem(2, item)
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.label_7 = QtWidgets.QLabel(self.tab_3)
        self.label_7.setGeometry(QtCore.QRect(50, 270, 51, 14))
        self.label_7.setText("")
        self.label_7.setObjectName("label_7")
        self.layoutWidget1 = QtWidgets.QWidget(self.tab_3)
        self.layoutWidget1.setGeometry(QtCore.QRect(0, 0, 1031, 41))
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout(self.layoutWidget1)
        self.horizontalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.textEdit = QtWidgets.QTextEdit(self.layoutWidget1)
        self.textEdit.setMaximumSize(QtCore.QSize(16777215, 30))
        self.textEdit.setObjectName("textEdit")
        self.horizontalLayout_7.addWidget(self.textEdit)
        self.button_capa_analyze = QtWidgets.QPushButton(self.layoutWidget1)
        self.button_capa_analyze.setObjectName("button_capa_analyze")
        self.horizontalLayout_7.addWidget(self.button_capa_analyze)
        self.capa_table = QtWidgets.QTableWidget(self.tab_3)
        self.capa_table.setGeometry(QtCore.QRect(0, 50, 1031, 501))
        self.capa_table.setObjectName("capa_table")
        self.capa_table.setColumnCount(2)
        self.capa_table.setRowCount(6)
        item = QtWidgets.QTableWidgetItem()
        self.capa_table.setVerticalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.capa_table.setVerticalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.capa_table.setVerticalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.capa_table.setVerticalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.capa_table.setVerticalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.capa_table.setVerticalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.capa_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.capa_table.setHorizontalHeaderItem(1, item)
        self.tabWidget.addTab(self.tab_3, "")
        self.layoutWidget2 = QtWidgets.QWidget(self.centralwidget)
        self.layoutWidget2.setGeometry(QtCore.QRect(0, 0, 2, 2))
        self.layoutWidget2.setObjectName("layoutWidget2")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.layoutWidget2)
        self.verticalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1064, 27))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(1)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.checkBox_pid.setText(_translate("MainWindow", "pid"))
        self.checkBox_exepath.setText(_translate("MainWindow", "exe-path"))
        self.checkBox_netactiuvity.setText(_translate("MainWindow", "network activity"))
        self.checkBox_sign.setText(_translate("MainWindow", "signature"))
        self.checkBox_packing.setText(_translate("MainWindow", "packing"))
        self.checkBox_sections.setText(_translate("MainWindow", "sections"))
        self.checkBox_capa.setText(_translate("MainWindow", "capa"))
        item = self.main_table.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "pid"))
        item = self.main_table.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "exe-path"))
        item = self.main_table.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "network activity"))
        item = self.main_table.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "signature"))
        item = self.main_table.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "packing"))
        item = self.main_table.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "sections"))
        item = self.main_table.horizontalHeaderItem(6)
        item.setText(_translate("MainWindow", "capa"))
        self.button_start_scan.setText(_translate("MainWindow", "Start scan"))
        self.button_stop_scan.setText(_translate("MainWindow", "Stop scan"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "Scan"))
        self.textEdit_2.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"hr { height: 1px; border-width: 0; }\n"
"li.unchecked::marker { content: \"\\2610\"; }\n"
"li.checked::marker { content: \"\\2612\"; }\n"
"</style></head><body style=\" font-family:\'Sans Serif\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</p></body></html>"))
        self.button_capa_analyze_2.setText(_translate("MainWindow", "Analyze"))
        item = self.table_codediff.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Section"))
        item = self.table_codediff.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Attributes"))
        item = self.table_codediff.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Diff percent"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "Code diff"))
        self.textEdit.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"hr { height: 1px; border-width: 0; }\n"
"li.unchecked::marker { content: \"\\2610\"; }\n"
"li.checked::marker { content: \"\\2612\"; }\n"
"</style></head><body style=\" font-family:\'Sans Serif\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">C:\\Users\\MrRobot\\Desktop\\SPBPU-MSPZA\\testcases\\test_capa.exe</p></body></html>"))
        self.button_capa_analyze.setText(_translate("MainWindow", "Analyze"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("MainWindow", "Capa"))
