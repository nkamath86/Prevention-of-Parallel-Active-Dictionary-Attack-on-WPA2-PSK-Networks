import threading
import time

exitFlag = 0
def print_time(threadName, delay, counter):
		while counter:
			if exitFlag:
				threadName.exit()
			time.sleep(delay)
			print "%s: %s" % (threadName, time.ctime(time.time()))
			counter -= 1



def read_in_chunks(file): 
  while True: 
  	data = file.readline()
  	if data:
  		yield data

class myThread (threading.Thread):
	def __init__(self, threadID, name, counter, file):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
		self.counter = counter
		self.file = file

	

	def run(self):
		print "Starting " + self.name
		print_time(self.name, self.counter, 5)
		for a in read_in_chunks(self.file):
			print a, self.name
		print "Exiting " + self.name
		self.exit()


#with open("C:/Users/Nagendra/Desktop/BE_PROJ/dictionary.txt",'r') as f:
#	for j in xrange(10):
#		n = open("C:/Users/Nagendra/Desktop/BE_PROJ/Dictionary_Splits/"+str(j)+".txt",'w')
#		for i in read_in_chunks(f):
#			n.write(i)

# Create new threads
f = open("/home/aneek/Desktop/3.txt")
thread1 = myThread(1, "Thread-1", 1, f)
thread2 = myThread(2, "Thread-2", 2, f)

# Start new Threads
thread1.start()
thread2.start()
thread1.join()
thread2.join()
print "Exiting Main Thread"
