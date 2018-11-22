#!/bin/python3
import paramiko
import argparse
import time
import socket

class bcolors:
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'


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
		print(bcolors.OKBLUE + "[*] " + bcolors.ENDC + "Testing connection... ")
		ssh.connect(hostname=host,port=port,username="invalid_username_for_only_get_the_banner",password="invalid_password_for_only_get_the_banner",timeout=timeout)
	
	except socket.timeout as exception:
		print(bcolors.FAIL + "[-] " + bcolors.ENDC + "Failed to get banner. ("+str(exception)+")")
	
	except Exception as exception:
		print(bcolors.OKBLUE + "[*] " + bcolors.ENDC + "Getting banner... ")
		banner=""

		if(ssh.get_transport()): 
			banner=ssh.get_transport().remote_version
			print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + "Banner => "+banner)
		else:
			print(bcolors.FAIL + "[-] " + bcolors.ENDC + "Failed to get banner. ("+str(exception)+")")
		ssh.close()
		


def test_connection(host,port,username,password,timeout):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh.connect(hostname=host,port=port,username=username,password=password,timeout=timeout)
		print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + "Test connection succeed (Credentials are valid) => " +host+":"+str(port))
		ssh.close()
		return True

	except paramiko.AuthenticationException as exception:
		print(bcolors.FAIL + "[-] " + bcolors.ENDC + "Authentication Failed => " +host+":"+str(port))
		return False

	except Exception as exception:
		print(bcolors.FAIL + "[-] " + bcolors.ENDC + "Failed to connect => " +host+":"+str(port)+" ("+str(exception)+")")
		return False

	finally:
		ssh.close()

def send_command(host,port,username,password,timeout,command):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh.connect(hostname=host,port=port,username=username,password=password,timeout=timeout)
		print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + "Established connection => " +host+":"+str(port))
		rm=ssh.invoke_shell()


# Aşağıdaki alana dilediğiniz komutları girebilirsiniz. örn.=> rm.send("enable\n") rm.send("Y\n") rm.send("password\n")
########################################

		rm.send("?\n")
		rm.send("\n")
		rm.send("\n")
		rm.send("\n")
		rm.send("\n")
		rm.send("\n")
		rm.send("\n")
		rm.send("\n")

########################################


		time.sleep(1)
		output = str(rm.recv(131989504))
		output=output.replace("\\r\\n", "\n")[2:]
		output=output[0:len(output)-1]
		print(output)
		print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + "Command execution succeed")

	except Exception as exception:
		print(bcolors.FAIL + "[-] " + bcolors.ENDC + "Crashed => " +host+":"+str(port)+" ("+str(exception)+")")

	finally:
		ssh.close()


def main():
	global args
	args = get_args()

	timeout = 3
	host = args.host
	port = args.port
	username = args.username
	password = args.password

	get_banner(host,port,timeout)
	if(test_connection(host,port,username,password,timeout) is False):
		print(bcolors.OKBLUE+ "[*] " + bcolors.ENDC + "Exiting...")
	else:
		command="ls -la"
		send_command(host,port,username,password,timeout,command)



if __name__ == "__main__":
	main()
