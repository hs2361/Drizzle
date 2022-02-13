from PyQt5 import QtCore, QtWidgets


class QToggleSwitch(QtWidgets.QSlider):
    toggled = QtCore.pyqtSignal()
    switchedOn = QtCore.pyqtSignal()
    switchedOff = QtCore.pyqtSignal()

    def __init__(self, default=0):
        QtWidgets.QSlider.__init__(self, QtCore.Qt.Horizontal)
        self.setMaximumWidth(30)
        self.setMinimum(0)
        self.setMaximum(1)
        self.setSliderPosition(default)
        self.sliderReleased.connect(self.toggle)

    def toggle(self):
        if self.value == 1:
            self.setSliderPosition(0)
            self.setValue(0)
            self.toggled.emit()
            self.switchedOff.emit()

        else:
            self.setSliderPosition(1)
            self.setValue(0)
            self.toggled.emit()
            self.switchedOn.emit()

    def isOn(self):
        return self.currentValue
