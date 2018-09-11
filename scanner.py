import requests
import re
from urllib.parse import *
from bs4 import BeautifulSoup

class Scanner:
	def __init__(self,url,ignore_links):
		self.target_url = url
		self.target_links = []
		self.session = requests.Session()
		self.links_to_ignore = ignore_links

	def extract_links_form(self):
		response = self.session.get(self.target_url)
		return re.findall('(?:href=")(.*?)"',response.text)

	def crawl(self,url=None):
		if url == None:
			url = self.target_url
		href_links = self.extract_links_form()
		for link in href_links:
			link = urljoin(url, link)

			if '#' in link:
				print(link)
				link = link.split('#')[0]

			if self.target_url in link and link not in self.target_links:
				if '.css' not in link and '.ico' not in link:
					self.target_links.append(link)
					print('[+] ',link)
					self.crawl(link)

	def get_payloads(self):
		with open('xss_payloads.txt') as file:
			for line in file.readlines():
				line = line.strip()
				yield line

	def extract_forms(self,url):
		response = requests.get(url)
		soup_obj = BeautifulSoup(response.text,'lxml')
		list_forms = soup_obj.findAll('form')
		return list_forms

	def inject_payload(self,url):
		list_forms = self.extract_forms(url)
		xss_payload = []
		for payload in self.get_payloads():
			xss_payload.append(payload)

		for form in list_forms:
			input_box = form.findAll('input')
			post_data = {}

			for i in range(len(xss_payload)):
				for box in input_box:
					box_name = box.get('name')
					type_box = box.get('type')
					input_value = box.get('value')
					if type_box == 'text':
						input_value = xss_payload[i]

					post_data[box_name]=input_value

				result = requests.post(url,data=post_data)
				#print(result.text)
				if xss_payload[i] in result.text:
					print('\n[!] VULNERABILITY DETECTED!--> ' + xss_payload[i])
					print('[*] LINK IS ',url)
					print('---FORM DATA---')
					print(form)
					print('\n')
				else:
					print("[+] OK. \n")

	def run(self):
		print("XSS Scanner running...\n \n")
		self.crawl()
		for url in self.target_links:
			self.inject_payload(url)
