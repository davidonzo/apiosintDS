#!/usr/bin/env python3
from apiosintDS import apiosintDS

try:
        OSINTCHECK = apiosintDS.request(
                                        entities=['192.168.1.54',
                                                  '10.12.12.10',
                                                  'somehost.ext',
                                                  'http://www.example.com/malicious.exe'],
                                        verbose=True)
        print(OSINTCHECK) # print dict results
except:
        print("Some error") # some error
