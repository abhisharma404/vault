"""This is the main engine of the program"""

import requests
import re
from bs4 import BeautifulSoup

class Scanner:
	def __init__(self,url,payload):
		self.target_url = url
		self.payload = payload

	def extract_forms(self):
		response = requests.get(self.target_url)
		soup_obj = BeautifulSoup(response.text,'lxml')
		list_forms = soup_obj.findAll('form')
		return list_forms

	def inject_payload(self):
		list_forms = self.extract_forms()

		for form in list_forms:
			input_box = form.findAll('input')
			post_data = {}

			for i in range(len(self.payload)):
				for box in input_box:
					box_name = box.get('name')
					type_box = box.get('type')
					input_value = box.get('value')
					if type_box == 'text':
						input_value = self.payload[i]

					post_data[box_name]=input_value

				result = requests.post(self.target_url,data=post_data)

				if self.payload[i] in result.text:
					print('\n[!] VULNERABILITY DETECTED!--> ' + self.payload[i])
					print('[*] LINK IS ',self.target_url)
					print('---FORM DATA---')
					print(form)
					print('\n')
				else:
					print("[+] OK. \n")
