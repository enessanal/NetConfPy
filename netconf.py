#!/bin/python3.6
import paramiko, argparse,time,socket,os,platform

def paint(text,color):
	GREEN = '\033[92m'
	BLUE = '\033[94m'
	RED = '\033[91m'
	YELLOW = '\033[1;33m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	RESET = '\033[0m'

	if OS_is_Linux is False: 
		return text

	if color is "GREEN" : 
		return GREEN + text + RESET

	elif color is "BLUE" : 
		return BLUE + text + RESET

	elif color is "RED" : 
		return RED + text + RESET

	elif color is "YELLOW" : 
		return YELLOW + text + RESET

	elif color is "BOLD" : 
		return BOLD + text + RESET

	elif color is "UNDERLINE" : 
		return UNDERLINE + text + RESET

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
		print(paint("[*] ","BLUE") + "Testing connection... ")
		ssh.connect(hostname=host,port=port,username="invalid_username_for_only_get_the_banner",password="invalid_password_for_only_get_the_banner",timeout=timeout)
	
	except socket.timeout as exception:
		print(paint("[-] ","RED") + "Failed to get banner. ("+str(exception)+")")
	
	except Exception as exception:
		print(paint("[*] ","BLUE") + "Getting banner... ")
		banner=""

		if(ssh.get_transport()): 
			banner=ssh.get_transport().remote_version
			print(paint("[+] ","GREEN") + "Banner => "+banner)

		else:
			print(paint("[-] ","RED") + "Failed to get banner. ("+str(exception)+")")

		ssh.close()
		
def test_connection(host,port,username,password,timeout):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh.connect(hostname=host,port=port,username=username,password=password,timeout=timeout)
		print(paint("[+] ","GREEN") + "Test connection succeed (Credentials are valid) => " +host+":"+str(port))

		ssh.close()
		return True

	except paramiko.AuthenticationException as exception:
		print(paint("[-] ","RED") + "Authentication failed => " +host+":"+str(port))
		
		return False

	except Exception as exception:
		print(paint("[-] ","RED") + "Failed to connect => " +host+":"+str(port)+" ("+str(exception)+")")

		return False

	finally:
		ssh.close()

def activate_shell(host,port,username,password,timeout):
	
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		print(paint("[*] ","BLUE") + "Preparing for execution... ")
		ssh.connect(hostname=host,port=port,username=username,password=password,timeout=timeout)
		print(paint("[+] ","GREEN") +"Established connection => " +host+":"+str(port))
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
		print(paint("[+] ","GREEN") + "Command execution succeed")

	except Exception as exception:
		print(paint("[-] ","RED") + "Crashed => " +host+":"+str(port)+" ("+str(exception)+")")

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
		print(paint("[*] ","BLUE") + "Exiting...")
	else:
		activate_shell(host,port,username,password,timeout)





if __name__ == "__main__":
	main()
