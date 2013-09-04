#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ---------------------------------------------------
# Copyright (c) 2013 Pablo Caro. All Rights Reserved.
# Pablo Caro <me@pcaro.es> - http://pcaro.es/
# ProgressBar.py
# ---------------------------------------------------

import sys


class ProgressBar:
    def __init__(self, min=0, max=100, width=60, charset='[=]'):
        self.min = min
        self.max = max
        self.width = width
        self.current = min
        self.percent = 0.0
        self.int_percent = 0

        if len(charset) != 3:
            charset = '[=]'
        self.charset = charset

        self.bar = ''
        self.used = -1
        self.int_percent_change = False

    def update(self, current):
        self.current = current
        self.percent = (float(self.current-self.min)/(self.max-self.min))*100.0
        int_percent = int(self.percent)

        if int_percent != self.int_percent:
            self.int_percent_change = True
        self.int_percent = int_percent

        self.__generate_bar__()

        if self.int_percent_change:
            self.int_percent_change = False
            return True
        else:
            return False

    def show(self):
        sys.stdout.write(str(self))
        sys.stdout.flush()

    def __str__(self):
        return self.bar

    def __generate_bar__(self):
        self.used = int((float(self.current-self.min)/(self.max-self.min)) *
                        (self.width-6))

        center = self.charset[1] * self.used
        self.bar = (self.charset[0] + center + self.charset[2]
                    + " " + str(self.int_percent) + '%' + '\r')


def main():
    pass

if __name__ == '__main__':
    main()
