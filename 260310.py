from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout
from PyQt5.QtCore import QTimer, QDateTime, Qt
from PyQt5.QtGui import QFont, QFontDatabase
from qfluentwidgets import FluentWindow, SubtitleLabel, FluentIcon, BodyLabel
import sys


class HomePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("HomePage")
        
        # 加载HarmonyOS_Sans
        font_id = QFontDatabase.addApplicationFont("font/HarmonyOS_Sans/HarmonyOS_Sans_Black.ttf")
        font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
        
        layout = QVBoxLayout(self)
        
        # 添加页面标题
        title_label = SubtitleLabel("主页", self)
        title_font = QFont(font_family)
        title_font.setPointSize(32)
        title_label.setFont(title_font)
        layout.addWidget(title_label)
        
        #time
        self.timeLabel = BodyLabel("", self)
        font = QFont(font_family)
        font.setPointSize(72)
        self.timeLabel.setFont(font)
        self.timeLabel.setStyleSheet("color: black;")
        self.timeLabel.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.timeLabel)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.updateTime)
        self.timer.start(1000)
        self.updateTime()
        
        layout.addStretch(1)
    
    def updateTime(self):
        current_time = QDateTime.currentDateTime().toString("HH:mm:ss")
        self.timeLabel.setText(current_time)


class SettingsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("SettingsPage")
        
        # 加载HarmonyOS_Sans
        font_id = QFontDatabase.addApplicationFont("font/HarmonyOS_Sans/HarmonyOS_Sans_Regular.ttf")
        font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
        
        layout = QVBoxLayout(self)
        
        # 添加页面标题和内容
        layout.addWidget(SubtitleLabel("设置 页面", self))
        content_label = BodyLabel("这里是设置页面的内容", self)
        content_label.setFont(QFont(font_family))
        layout.addWidget(content_label)
        layout.addStretch(1)


class DoneApp(FluentWindow):
    def __init__(self):
        super().__init__()
        
        # 设置窗口标题
        self.setWindowTitle("Done")
        
        self.homePage = HomePage(self)
        self.settingsPage = SettingsPage(self)
        
        # 初始化导航栏
        self.initNavigation()
        
        # 设置窗口大小
        self.resize(1000, 700)
        self.setMinimumSize(600, 400)
    
    def initNavigation(self):
        self.addSubInterface(self.homePage, FluentIcon.HOME, "主页")
        self.addSubInterface(self.settingsPage, FluentIcon.SETTING, "设置")
        
        self.navigationInterface.setCurrentItem(self.homePage.objectName())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    window = DoneApp()
    
    window.show()
    
    # 运行应用
    sys.exit(app.exec_())
