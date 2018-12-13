from urllib.parse import unquote
import colors
import requests
from bs4 import BeautifulSoup
import sys

def modifyLINK(url):
	list1=[]
	for ch in url:
		if ch=="&":
			break
		else:
			list1.append(ch)
	ret=''.join(list1)
	return ret

def savetofile(URLlist):
	response=str(input("\n\033[1;31mDo you want to save it in a file (yes/no):: \033[1;37m"))
	if response == "yes":
		name=str(input("\033[1;31mGive file name :: \033[1;37m"))
		if name.endswith(".txt")==False:
			l = name+".txt"
		else:
			l=name
		f_open = open(l,"w")
		for url in URLlist:
			f_open.write(url + "\n")
		f_open.close()
		print("\033[1;32mYour file has been saved successfully")

def start_dorking(search,page_count):
    web_list=[]
    m_search=modifyLINK(search)
    count=0
    page_count*=10
    while (page_count!=count):
        count=str(count)
        m_search=str(m_search)
        search_url="https://google.com/search?q="+m_search+"&start="+count
        requested_page=requests.get(search_url).text
        soup=BeautifulSoup(requested_page,'html.parser')
        count=int(count)
        if "Our systems have detected unusual traffic from your computer network" in soup.get_text():
            colors.error("Google has detected the script. Try after some time.")
            LOGGER.error('[-] script blocked by google. wait for some minutes')
            break
        h3_tags=soup.findAll("h3")
        for h3 in h3_tags:
            a_tag=h3.find("a")
            link=a_tag.get("href")
            link=link[7:]
            if link.startswith("http"):
                searchlink=modifyLINK(link)
                res=unquote(searchlink)
                web_list.append(res)
                print("\033[1;37m--> \033[1;32m",res,end=" \n")
        count+=10
    savetofile(web_list)
    sys.exit(0)
    return web_list
