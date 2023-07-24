import argparse
import requests
import socket
import time
from bs4 import BeautifulSoup

def __banner__():
	print('''
 _____                       
|  |  |___ ___ _____ ___ ___ 
|  |  | .'|  _|     | .'| . |
 \___/|__,|_| |_|_|_|__,|  _|
                        |_|  
        Copyright : Pham Chien
        Team : GhostMan Security
''')

def __session__():
	argparsers = argparse.ArgumentParser(description="VarMap Tool - Exploring Website Information")
	argparsers.add_argument('--url', type=str, help='URL target (ex : https://test.com)')
	argparsers.add_argument('--check', action='store_true', help='Checking target URL')
	argparsers.add_argument('--version', action='store_true', help='Checking Version Target URL')
	argparsers.add_argument('--propertie', action='store_true', help='Scanning ALL Propertie URL Target')
	argparsers.add_argument('--infomation', action='store_true', help='Scanning ALL Infomation URL Target')
	argparsers.add_argument('--filter', action='store_true', help='Scanning ALL Filter URL Target')
	argparsers.add_argument('--meta', action='store_true', help='Checking Items META URL target')
	argparsers.add_argument('--link', action='store_true', help='Checking Items LINKS URL target')
	argparsers.add_argument('--script', action='store_true', help='Checking Items script URL target')
	argparsers.add_argument('--about', action='store_true', help='Show This About')

	args = argparsers.parse_args()

	URL = args.url
	CHECK = args.check
	VER = args.version

	if URL:
		if CHECK:
			print("[info] starting check response from {}".format(URL))
			response = requests.get(URL)
			if response.status_code == 200:
				print("[info] the target URL as responsed , status code : 200")
				time.sleep(0.90)
				print("[info] starting checking...")
				time.sleep(1)
				def __check__():
					your_domain = URL.replace("http://", "").replace("https://", "")
					remove_http = your_domain.split("://")
					URL_new = remove_http[-1]
					remove = URL_new.replace("/", "")
					results = remove.split("/")
					remove_now = results[-1]
					get_ip = socket.gethostbyname(remove_now)
					print("Target : {}".format(remove_now))
					time.sleep(0.50)
					print("Server : {}".format(get_ip))
				__check__()

				if VER:
					code = response.raw.version
					print("Version HTTP : ", code)

				if args.propertie:
					properties = dir(response)
					for line in properties:
						print("properties : {}".format(line))
						time.sleep(0.10)
				if args.infomation:
					soup = BeautifulSoup(response.text, 'html.parser')
					script = soup.find_all('script')
					link = soup.find_all('link')
					for lines in script:
						print("[info] script java : {}".format(lines))
						time.sleep(0.10)
					for lines in link:
						print("[info] link : {}".format(lines))
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
									print("[info] filter : {} : {}".format(data, line))
									time.sleep(0.50)
								else:
									print("[info] No Filter..")
					__getfilter__()
				if args.meta:
					def __getmeta__():
						meta_script = BeautifulSoup(response.text, 'html.parser')
						scanning = meta_script.find_all('meta')
						for line_meta in scanning:
							print("[info] Meta Line : {}".format(line_meta))
							time.sleep(0.10)
					__getmeta__()

				if args.link:
					def __getlink__():
						get_link = BeautifulSoup(response.text, 'html.parser')
						link = get_link.find_all('link')
						for line in link:
							print("[info] Link Line : {}".format(line))
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
					
			else:
				print("[warning] the target not response, please agian")
				exit()
		else:
			print("[info] you not set payload checking")
	else:
		print("Usage : python varmap.py --url <http://test.com> --check --version")
		print("Typer Command : python varmap.py -h for help")
		print('''
VarMap Tool - Exploring Website Information
Technology is constantly evolving, and websites have become an integral part of modern life. However, with the increasing popularity of websites, managing information on them has also become more complex. That's where the VarMap tool comes in, providing an effective solution for scanning and discovering information from a website.

VarMap, short for "Variable Mapping," is a scanning tool designed to search for and collect information from a specific website. By using VarMap, users can easily identify the structure and various components of the target website. This is extremely useful for analyzing and extracting information from large and complex websites.

VarMap operates by scanning the entire website and generating a detailed map of variables and key components of that website. The tool utilizes syntax analysis techniques to search for HTML, CSS, JavaScript, and other languages used within the website. Then, VarMap organizes and stores this information in a tree-like structure so that users can easily visualize the entire website's structure.

One of the significant advantages of VarMap is its compatibility with various types of websites such as blogs, online stores, or forums. This helps users save time and effort when understanding the structure of a new website they are unfamiliar with.

VarMap provides powerful features for extracting information from websites. Users can identify variables, constants, classes, and IDs of components on the website. Furthermore, VarMap allows users to search for specific attributes such as URLs, emails, phone numbers, and various types of information. The tool offers a simple and user-friendly interface, enabling users to search and store information according to their needs.

VarMap is not only useful for analyzing and extracting information from websites but also helps users check the security of a website. The tool can detect security vulnerabilities by searching for malicious code segments or weaknesses in the website's structure.

In practice, the VarMap tool is capable of saving time, improving efficiency, and enhancing the ability to analyze information from websites. By combining the power of automation with user-friendly interfaces, VarMap is a valuable tool for anyone who needs to explore and extract information from websites effectively.
	''')
		exit()

	if args.about:
		print('''
VarMap Tool - Exploring Website Information
Technology is constantly evolving, and websites have become an integral part of modern life. However, with the increasing popularity of websites, managing information on them has also become more complex. That's where the VarMap tool comes in, providing an effective solution for scanning and discovering information from a website.

VarMap, short for "Variable Mapping," is a scanning tool designed to search for and collect information from a specific website. By using VarMap, users can easily identify the structure and various components of the target website. This is extremely useful for analyzing and extracting information from large and complex websites.

VarMap operates by scanning the entire website and generating a detailed map of variables and key components of that website. The tool utilizes syntax analysis techniques to search for HTML, CSS, JavaScript, and other languages used within the website. Then, VarMap organizes and stores this information in a tree-like structure so that users can easily visualize the entire website's structure.

One of the significant advantages of VarMap is its compatibility with various types of websites such as blogs, online stores, or forums. This helps users save time and effort when understanding the structure of a new website they are unfamiliar with.

VarMap provides powerful features for extracting information from websites. Users can identify variables, constants, classes, and IDs of components on the website. Furthermore, VarMap allows users to search for specific attributes such as URLs, emails, phone numbers, and various types of information. The tool offers a simple and user-friendly interface, enabling users to search and store information according to their needs.

VarMap is not only useful for analyzing and extracting information from websites but also helps users check the security of a website. The tool can detect security vulnerabilities by searching for malicious code segments or weaknesses in the website's structure.

In practice, the VarMap tool is capable of saving time, improving efficiency, and enhancing the ability to analyze information from websites. By combining the power of automation with user-friendly interfaces, VarMap is a valuable tool for anyone who needs to explore and extract information from websites effectively.
''')
		exit()

if __name__ == '__main__':
	__banner__()
	__session__()
