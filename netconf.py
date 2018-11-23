#!/bin/python3.6
import paramiko
import argparse
import time
import socket
import os
import platform

class bcolors:
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'

def paint(text,color):
	if OS_is_Linux is False: 
		return text

	if color is "OKGREEN" : 
		return bcolors.OKGREEN + text + bcolors.ENDC

	elif color is "OKBLUE" : 
		return bcolors.OKBLUE + text + bcolors.ENDC

	elif color is "FAIL" : 
		return bcolors.FAIL + text + bcolors.ENDC
		
	elif color is "UNDERLINE" : 
		return bcolors.UNDERLINE + text + bcolors.ENDC
		
	elif color is "WARNING" : 
		return bcolors.WARNING + text + bcolors.ENDC

	else: 
		return text

def get_args():
	parser=argparse.ArgumentParser(description='NetConfPy - Target Spesific Configurator',add_help=False)
	parser.add_argument("host",type = str, help="Give a host name or device IP address.")
	parser.add_argument("username", type = str, help = "Give a user name")
	parser.add_argument("password", type = str, help = "Give a password")
	parser.add_argument("-p","--port",help="Port Number (Default=22)",type=int,default=22)

	args=parser.parse_args()
	return args;


def get_banner(host,port,timeout):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	try:
		print(paint("[*] ","OKBLUE") + "Testing connection... ")
		ssh.connect(hostname=host,port=port,username="invalid_username_for_only_get_the_banner",password="invalid_password_for_only_get_the_banner",timeout=timeout)
	
	except socket.timeout as exception:
		print(paint("[-] ","FAIL") + "Failed to get banner. ("+str(exception)+")")
	
	except Exception as exception:
		print(paint("[*] ","OKBLUE") + "Getting banner... ")
		banner=""

		if(ssh.get_transport()): 
			banner=ssh.get_transport().remote_version
			print(paint("[+] ","OKGREEN") + "Banner => "+banner)

		else:
			print(paint("[-] ","FAIL") + "Failed to get banner. ("+str(exception)+")")

		ssh.close()
		


def test_connection(host,port,username,password,timeout):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh.connect(hostname=host,port=port,username=username,password=password,timeout=timeout)
		print(paint("[+] ","OKGREEN") + "Test connection succeed (Credentials are valid) => " +host+":"+str(port))

		ssh.close()
		return True

	except paramiko.AuthenticationException as exception:
		print(paint("[-] ","FAIL") + "Authentication Failed => " +host+":"+str(port))
		
		return False

	except Exception as exception:
		print(paint("[-] ","FAIL") + "Failed to connect => " +host+":"+str(port)+" ("+str(exception)+")")

		return False

	finally:
		ssh.close()

def activate_shell(host,port,username,password,timeout):
	
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		print(paint("[*] ","OKBLUE") + "Preparing for execution... ")
		ssh.connect(hostname=host,port=port,username=username,password=password,timeout=timeout)
		print(paint("[+] ","OKGREEN") +"Established connection => " +host+":"+str(port))
		########################################################################################
		rm=ssh.invoke_shell()
		rm.send("uname -a\n")








		#########################################################################################

		time.sleep(1)
		output = str(rm.recv(131989504))
		output=output.replace("\\r\\n", "\n")[2:]
		output=output[0:len(output)-1]
		print()
		print(output)
		print()
		print(paint("[+] ","OKGREEN") + "Command execution succeed")

	except Exception as exception:
		print(paint("[-] ","FAIL") + "Crashed => " +host+":"+str(port)+" ("+str(exception)+")")

	finally:
		ssh.close()


def main():
	global OS_is_Linux
	OS_is_Linux = True
	if platform.system() is "Windows" : 
		OS_is_Linux = False

	global args
	args = get_args()

	timeout = 5
	host = args.host
	port = args.port
	username = args.username
	password = args.password

	get_banner(host,port,timeout)
	if(test_connection(host,port,username,password,timeout) is False):
		print(paint("[*] ","OKBLUE") + "Exiting...")
	else:
		activate_shell(host,port,username,password,timeout)








if __name__ == "__main__":
	main()
