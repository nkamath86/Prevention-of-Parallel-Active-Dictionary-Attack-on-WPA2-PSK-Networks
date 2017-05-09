# with open("C:/Users/Nagendra/Desktop/BE_PROJ/crackstation-human-only.txt/realhuman_phill.txt",'r') as f:
# 	lisst = f.readlines()

# with open("C:/Users/Nagendra/Desktop/BE_PROJ/1.txt",'w') as n:
# 	n.write("".join(lisst))

# with open("C:/Users/Nagendra/Desktop/BE_PROJ/dictionary.txt",'r') as f:
# 	with open("C:/Users/Nagendra/Desktop/BE_PROJ/1.txt",'w') as n:
# 		for line in f:
# 			n.write(line)


def read_in_chunks(file, chunk_size=52428800): 
   # while True: 
   # 104857600
  data = file.read(chunk_size) 
  if data:
  	yield data

with open("/home/nagendra/Desktop/2.txt",'r') as f:
	for j in xrange(2):
		n = open("/home/nagendra/Desktop/"+str(j)+".txt",'w')
		for i in read_in_chunks(f):
			n.write(i)
