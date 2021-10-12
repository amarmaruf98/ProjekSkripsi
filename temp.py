# import random
# import re
# from urllib.parse import urlparse,urlencode

# x=0
# fwrite=open("urllegi2021.txt","w")
# temp=[]

# def getdomain(url):
#     domain=urlparse(url).netloc
#     # print(domain)
#     if re.match(r"^www.",domain):
#         domain=domain.replace("www.","")    
#     return domain

# # url=input("Masukan linknya: ")
# # domain=getdomain(url)
# # fwrite=open("domainlist2021.txt","w")
# with open("ALL-phishing-links/ALL-phishing-links.txt", "r") as fu:
# # with open("ALL-phishing-domains/ALL-phishing-domains.txt", "r") as fu:
#     w=sorted(fu, key=lambda k: random.random())
#     # for url1 in fu:
#     #     x+=1
#     #     url1=url1.replace("\n","")
#     #     if domain == url1:
#     #         print(x)
#     #         print("match")
#     #         print(url)
#     #         print("=======")
#     #         print(url1)
#     #         break







#     # print(type(w))

# for i in w:
#     # i=i.replace("\n","")
#     i=i.replace('"',"")
#     x+=1
#     print(i)
#     temp.append(i)
#     # fwrite.writelines(str(i))
#     if x == 2021:
#         print("done")
#         break

# for ll in temp:
#     fwrite.write(ll)



    


# # f = open("ALL-phishing-links/ALL-phishing-links.txt")
# # lines = f.readlines() 

# # rand_line = random. randint(0,len(lines)-1) # this should make it work
# # print(lines[rand_line])

# # words = ["python", "java", "constant", "immutable","Amar","Sulis"]

from http.client import responses
from math import e
from os import stat
from bs4 import BeautifulSoup
import pandas as pd
from urllib.parse import urlparse,urlencode
import re
import requests
from datetime import datetime
from tldextract.tldextract import ExtractResult
import xlrd, random
import tldextract
import time, whois
import urllib.request

def connect(host='http://google.com'):
    try:
        urllib.request.urlopen(host) #Python 3.x
        return True
    except:
        return False

def getrequest(url):
    try:
        response=requests.get(url, timeout=8)
        soup=BeautifulSoup(response.text, features="lxml")
        print(response.status_code)
        if response.status_code != 200:
            response=1
        else:
            response=0
    except:
        response=1
        soup=-999
    return response, soup       
        

def getwhitelistresult(url):
    domain=getdomain(url)
    with open("clean_whitelist.txt", "r") as fu:
        for a in fu:
            # link=a
            a=a.replace("\n","")
            a=a.replace("www.","")
            if domain==a:
                value=-1
                link=url
                break
            else:
                value=0
                link=url
    
    # print("ini value: ",value)  
             
    if value == -1:
        return value, link
    else:
        return value, link

def getblacklistresult(url):
    domain=getdomain(url)
    with open("domainlist2021.txt", "r") as fu:
        for a in fu:
            # link=a
            a=a.replace("\n","")
            a=a.replace("www.","")
            if domain==a:
                value=2
                link=url
                domain=a
                break
            else:
                value=0
                link=url
                domain="no match"
    
    # print("ini value: ",value)  
             
    if value == 2:
        return value, link, domain
    else:
        return value, link, domain
   


def getdomain(url):
    # print(url)
    domain=urlparse(url).netloc
    # print(domain)
    if re.match(r"^www.",domain):
        domain=domain.replace("www.","")

    domain=domain.replace('\n','')    
    return domain

def connect(host='http://google.com'):
    try:
        urllib.request.urlopen(host) #Python 3.x
        return True
    except:
        return False


def FeatureExtract(url):
    
    url=url.replace("\t","")
    print("Extracting the data [{}]".format(url))
    fitur=[]
    domain=getdomain(url)
    response, soup=getrequest(url)
    fitur.append(domain)
    # print("Domain ",len(fitur))
    # fitur.append(response)
    # print(response)
    if response==1:
        # fitur.append(1)
        data=1
        link=url
    elif response==0:
        dom1,dom2=getwhitelistresult(url)
        if dom1 == -1:
            data=-1
            link=dom2
            # print(link)
            # fitur.append(-1)
        elif dom1 == 0:
            dom1,dom2,dom3=getblacklistresult(url)
            if dom1 == 2:
                data=2
                link=dom2
                domain=dom3
            elif dom1==0:
                data=0
                link=url
                domain=dom3
            # print(link)
            # fitur.append(0)
    return data, link, domain

x=0
print( 'Internet Connected' if connect() else 'No Internet Access!' )
with open("url.txt","r") as fh:
    w=sorted(fh, key=lambda k: random.random())
    
for i in w:
    x+=1
    i=i.replace('\n','')
    i=i.replace('\t','')
    
    print(FeatureExtract(i))
    if x==100:
        print("Done")
        break
