# example usage => python netconf.py "1.1.1.1" "myusername "mypassword"
import paramiko
import argparse

parser=argparse.ArgumentParser(description='NetConfPy - Target Spesific Configurator',add_help=False)
parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,help='This help message.')
parser.add_argument("ip",help="Device IP address.")
parser.add_argument("username",help="Username")
parser.add_argument("password",help="Password")
parser.add_argument("-p","--port",help="Port Number (Default=22)",type=int,default=22)

args=parser.parse_args()

ip = args.ip
port = args.port
username = args.username
password = args.password


try: 
	sshClient = paramiko.SSHClient()
	sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	sshClient.connect(ip,port,username,password)
	print("=> Connecting...")
	
	stdin,stdout,stderr = sshClient.exec_command("enable")
	stdin,stdout,stderr = sshClient.exec_command("configure terminal")
	

	sshClient.close()
	
except Exception as e:	
	print(str(e))
	
	try:
		sshClient.close()
		
	except Exception as e:	
		print(str(e))

		
		
		
		
		
		
		
		
		
		