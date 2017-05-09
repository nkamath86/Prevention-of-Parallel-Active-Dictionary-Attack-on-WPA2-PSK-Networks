#!/usr/bin/python
import threading
from threading import Thread
import time

# Define a function for the thread

class thread(Thread):
    def __init__(self,threadID,name,counter):
        Thread.__init__(self)
        self.threadID=threadID
        self.name=name
        self.counter=counter

   # def print_time(name,counter):
   #     count = 0
   #     while count < 5:
   #         time.sleep(100)
   #         count += 1
   #         print ("%s: %s" % ( name, time.ctime(time.time()) ))

    
   
    def run(self):
        print("starting..." +self.name,end="\n")
        
        

        print("Exiting...")
    

thread1= thread(1,"thread1",1)
thread2= thread(2,"thread2",2)
thread3= thread(3,"thread2",3)
# Create two threads as follows
try:
    thread1.start() 
    thread2.start()
    thread3.start()
except:
    print ("Error: unable to start thread")

while 1:
    pass
