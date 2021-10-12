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
import xlrd
import tldextract
import time
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
        # print("ini status code: ",response.status_code)
        link02=url
        response1=response
        if response.status_code != 200:
            response=1
        else:
            response=0
    except:
        link02=url
        response1=None
        response=1
        soup=-999
    return response, soup, link02, response1     
        

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
    domain1=domain.replace('\n','')
    with open(r"C:\Users\Amar\OneDrive - Bina Nusantara University\Skripsi OTW\ML Web\ALL-phishing-domains\ALL-phishing-domains.txt", "r") as fu:
        for a in fu:
            # link=a
            a=a.replace("\n","")
            a=a.replace("www.","")
            if domain1==a:
                value=2
                link=url
                break
            else:
                value=0
                link=url
    
    # print("ini value: ",value)  
             
    if value == 2:
        return value, link
    else:
        return value, link
   


def getdomain(url):
    # print(url)
    domain=urlparse(url).netloc
    # print(domain)
    if re.match(r"^www.",domain):
        domain=domain.replace("www.","")    
    return domain

def httpremove(domain):
    if re.match(r"^https://",domain):
        domain=domain.replace("https://","")
    else:
        domain=domain.replace("http://","")
    # else:
    #     pass
    return domain

def extractfavicon(url):
    # icon=1
    hal, soupweb, linkgr, response1=getrequest(url)
    if hal=="" or soupweb==-999:
        val=1
        return val
    else:
        iconweb=soupweb.find("link", rel="icon")
        if iconweb is None:
            iconweb=soupweb.find("link", rel="icon")
        if iconweb is None:
            return url + '/favicon.ico'
        return iconweb["href"]
        
    # try:
    #     hal=requests.get(url)
    #     soupweb=BeautifulSoup(hal.text, features="lxml")
        
    # except:
    #     return icon

def connect(host='http://google.com'):
    try:
        urllib.request.urlopen(host) #Python 3.x
        return True
    except:
        return False
    

def FeatureExtract(url, label):
    url=url.replace("\t","")
    print("Extracting the data [{}]".format(url))
    fitur=[]
    domain=getdomain(url)
    response, soup, linkgetrequest, response1=getrequest(url)
    fitur.append(domain)
    print("Domain ",len(fitur))
    print("amar")
    print("rizki p")
    # fitur.append(response)
    print("Ini response requestnya {} dari url {}".format(response1, linkgetrequest))
    if response==1:
        # fitur.append(1)
        data=1
        link=url
    elif response == 0:
        dom1,dom2=getwhitelistresult(url)
        if dom1 == -1:
            data=-1
            link=dom2
            # print(link)
            # fitur.append(-1)
        elif dom1==0:
            dom1,dom2=getblacklistresult(linkgetrequest)
            if dom1 == 2:
                data=2
                link=dom2
                # domain=dom3
            elif dom1==0:
                data=0
                link=dom2
                # domain=dom3
            
    # print("ini data: ",data)
    # print(link)
    domain2=getdomain(link)
    # print(data)
    
    # print(len(fitur))
    # try:
    #   print("Ini response text: ",response1.text)
    # except:
    #   print("Ini response text: ",response1)     
    
    
# 1. url length 
    
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)
    elif len(link) > 75:
        fitur.append(5)
    elif len(link) > 54 & len(link) < 75:
        fitur.append(4)
    else:
        fitur.append(3)
        
    # print(len(fitur))
    # 3 = non phishing -1
    # 4 = netral 
    # 5 = phishing 1
        
# 2
# slasdouble edited
    dom1=httpremove(link)
    sls='//'
    dom=dom1.find(sls)
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)
    elif dom != -1:
        fitur.append(5)
    else:
        fitur.append(3)
        
    # print(len(fitur))

# 3
# checkslash edited
    c=0
    for i in dom1:
        if i == '/':
            c=c+1
    # print(c)
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)
    elif c > 5:
        fitur.append(5)
    else:
        fitur.append(3)
        
    # print(len(fitur))
    
    # 4
    # having ip in url 
    url=getdomain(link)
    ipregex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)   
    elif (re.search(ipregex,url)):
        fitur.append(5)
    else:
        fitur.append(3)
        
    # print(len(fitur))

    # 5
    # check @
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)  
    elif "@" in link:
        fitur.append(5)
    else:
        fitur.append(3)
        
    # print(len(fitur))
        
    # 6
    # Hostlength 
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)  
    elif len(domain2) < 20:
        fitur.append(3)
    else:
        fitur.append(5)
        
    # print(len(fitur))
        
    # 7
    # https check 
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)  
    elif 'https' in link:
        fitur.append(3)
    else:
        fitur.append(5)
        
    # print(len(fitur))
    # 8
    # shorthening service
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
                      
    match=re.search(shortening_services,getdomain(link))
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2) 
    elif match:
        fitur.append(5)
    else:
         fitur.append(3)
         
    # print(len(fitur))
         
    # 9
    # check dash 
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2) 
    elif '-' in domain2:
        fitur.append(5)
    else:
        fitur.append(3)
        
    # print(len(fitur))
        
    # 10
    # check domain 
    domainsub=getdomain(link)
    domain3=tldextract.extract(domainsub)
    domain3=domain3.subdomain
    c=0
    for i in domain3:
        if i == '.':
            c=c+1
    
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)      
    elif c >= 1:
        fitur.append(5) 
    else:
        fitur.append(3) 
        
        
    # print(len(fitur))
        
    # 11
    # cek port 
    domain4=urlparse(link).port
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)
    elif domain4:
        fitur.append(5)
    else:
        fitur.append(3)
        
    # print(len(fitur))
    
    # 12
    # cek tanda petik
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)    
    elif ";" in link:
        fitur.append(3) 
    else:
        fitur.append(5) 
        
        
    # print(len(fitur))
    
    # 13
    # cek dan 
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)   
    elif "&" in link:
        fitur.append(5) 
    else:
        fitur.append(3) 
        
    # print(len(fitur))
    
    
    # 14
    # cek tandatanya
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)  
    elif "?" in link:
        fitur.append(5) 
    else:
        fitur.append(3) 
        
    # print(len(fitur))
    
    # 15
    # cek underscore
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)    
    elif "_" in link:
        fitur.append(5) 
    else:
        fitur.append(3) 
        
    # print(len(fitur))
        
    # 16
    # cek tld 
    dom3=tldextract.extract(link)
    dom3=dom3.suffix
    loc = r"tld_db.xlsx" 
    wb=xlrd.open_workbook(loc)
    sh=wb.sheet_by_index(0)
    sh.cell_value(0,0)
    for i in range(sh.nrows):
        tld=sh.cell_value(i,0)
        tld=tld.replace(".","")
        if dom==tld:
            val=-1
            break
        else:
            val=1
     
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)       
    elif val==-1:
        fitur.append(3) 
    else:
        fitur.append(5) 
        
    # print(len(fitur))
        
    # 17
    # Favicon cek 
    res=extractfavicon(link)
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)
    elif res==1:
        fitur.append(5)
    else:
        fitur.append(3)
        
    # print(len(fitur))
        
    # print(res)
    
    # 18
    # domain regis 
    # date1=whoisdata(link)
    # date1=date1
    # res=date1-today


    # # print(res)
    # if data==1:
    #     fitur.append(1) 
    # elif data==-1:
    #     fitur.append(-1)
    # elif res.days / 365 < 1 :
    #     fitur.append(1)
    # else:
    #     fitur.append(-1)
        
    # print(len(fitur))
    
    # 19
    # url anchor
    url=link
    percentage1 = 0
    i = 0
    unsafe = 0
    # print(soup)
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)
    # elif soup == -999:
    #     fitur.append(1)
    else:
        for a in soup.find_all('a', href=True):
            # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and :: might not be
                # there in the actual a['href']
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                unsafe = unsafe + 1
            i = i + 1

        try:
            percentage1 = unsafe / float(i) * 100
            # print(percentage)
        except:
            # fitur.append("Url anchor -1")
            percentage1=0
            # print('1')
            
        if percentage1 < 31.0:
            fitur.append(3)
        elif ((percentage1 >= 31.0) and (percentage1 < 67.0)):
            fitur.append(4)
        else:
            fitur.append(5)
            
    # print(len(fitur))
    
    # 20
    # link in tag         
    percentage=0
    i = 0
    success = 0
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)
    # elif soup == -999:
    #     fitur.append(1)
        # print(value)
    else:
        for link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if url in link['href'] or domain in link['href'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for script in soup.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if url in script['src'] or domain in script['src'] or len(dots) == 1:
                success = success + 1
            i = i+1
        try:
            percentage = success / float(i) * 100
            # print(percentage)
        except:
            # fitur.append("Link in tag -1")
            percentage=0

        if percentage < 17.0:
            fitur.append(3)
        elif ((percentage >= 17.0) and (percentage < 81.0)):
            fitur.append(4)
        else:
            fitur.append(5)
            
    # print(len(fitur))
    
    # 21
    # SFH  
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)     
    # elif soup==-999:
    #     fitur.append(1)
    elif len(soup.find_all('form', action=True))==0:
        fitur.append(3)
    else :
        for form in soup.find_all('form', action=True):
            if form['action'] == "" or form['action'] == "about:blank":
                fitur.append(5)
                break
            elif url not in form['action'] and domain not in form['action']:
                fitur.append(4)
                break
            else:
                fitur.append(3)
                break
            
    # print(len(fitur))
      
    # 22      
    # submiting to email
    # print("Submiting to email") 
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)       
    # elif response == 0:
    #     fitur.append(5)
    else:
      try:
        if re.findall(r"[mail\(\)|mailto:?]", response1.text):
            print("Masuk email")
            fitur.append(5)
        else:
            print("Tidak Masuk email")
            fitur.append(3)
      except:
        fitur.append(3)
            
    # print(len(fitur))
    
    # 23       
    # Redirect
    # print("Redirect") 
     
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)       
    # elif response == 0:
    #     fitur.append(5)
    else:
      try:
        if len(response1.history) <= 1:
             fitur.append(5)
        elif len(response1.history) <= 4:
             fitur.append(3)
        else:
             fitur.append(3)
      except:
        fitur.append(3)
             
    # print(len(fitur))
    
    # 24
    # on_mouseover 
    # print("Mouse over")       
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)       
    # elif response == 0:
    #     fitur.append(5)
    else:
      try:
        if re.findall("<script>.+onmouseover.+</script>", response1.text):
             fitur.append(3)
        else:
             fitur.append(5)
      except:
        fitur.append(5)
             
    # print(len(fitur))
    
    # 25
    # rigthclick
    # print("rigthclick")      
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)      
    # elif response == 0:
    #     fitur.append(5)
    else:
      try:
        if re.findall(r"event.button ?== ?2", response1.text):
             fitur.append(3)
        else:
             fitur.append(5)
      except:
        fitur.append(5)
             
             
    # print(len(fitur))
    # 26
    # popUpWidnow
    # print("PopUp Window")
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)       
    # elif response == 0:
    #     fitur.append(5)
    else:
      try:
        if re.findall(r"alert\(", response1.text):
             fitur.append(3)
        else:
             fitur.append(5)
      except:
        fitur.append(5)
             
             
    # print("26 ",len(fitur))

    # 27
    # Iframe
    # print("Iframe")
    if data==1:
        fitur.append(1)
    elif data==-1:
        fitur.append(-1)
    elif data==2:
        fitur.append(2)       
    # elif response == 0:
    #     fitur.append(5)
    else:
      try:
        if re.findall(r"[<iframe>|<frameBorder>]", response1.text):
             fitur.append(3)
        else:
             fitur.append(5)
      except:
        fitur.append(5)
             
    fitur.append(label)
    # print(len(fitur))
    return fitur

    
if __name__=="__main__":
    import threading
    starttime=time.time()
    print( 'Internet Connected' if connect() else 'No Internet Access!' )

    # def processdata():
    
    # dataphis=pd.read_csv("/content/drive/MyDrive/Colab Notebooks/mlskripsi/urlphis2021.txt",sep='\n')
    # # print(dataphis.head())
    # phisurl=dataphis.sample(n=100, random_state=12).copy()
    # phisurl=phisurl.reset_index(drop=True)
    # # print(phisurl.head(10))
    # print("Start to processing data......")
    # today=datetime.today()
        

    # datalegi=pd.read_csv("/content/drive/MyDrive/Colab Notebooks/mlskripsi/urllegi2021.txt",sep='\n')
    # # print(dataphis.head())
    # legiurl=datalegi.sample(n=100, random_state=12).copy()
    # legiurl=datalegi.reset_index(drop=True)

    # legi_url=[]
    # label=-1  
    # for i in range(0,100):
    #     url=legiurl['url'][i]
    #     legi_url.append(FeatureExtract(url, label))
        
    # feature_names = ['Domain', 'Length_URL', 'Slash_Double', 'Check_Slash', 'Having_Ip','Check_@','Hostlength','HTTPS_Check','Shortening_Service','check_dash','check_subdomain','check_port','Check_tandapetik','Check_Dan','Check_Tandatanya','Check_Underscore','Check_tld','Favicon','URL_Anchor','Link_in_Tag','SFH','Submiting_to_Email','Redirect_URL','On_MouseOver','RigthClick','PopUpWindows','Iframe','Label']

    # legitimate=pd.DataFrame(legi_url,columns=feature_names)


    # phis_url=[]
    # label=1
    # for i in range(0,100):
    #     url=phisurl['url'][i]
    #     phis_url.append(FeatureExtract(url, label))
        
    # feature_names = ['Domain', 'Length_URL', 'Slash_Double', 'Check_Slash', 'Having_Ip','Check_@','Hostlength','HTTPS_Check','Shortening_Service','check_dash','check_subdomain','check_port','Check_tandapetik','Check_Dan','Check_Tandatanya','Check_Underscore','Check_tld','Favicon','URL_Anchor','Link_in_Tag','SFH','Submiting_to_Email','Redirect_URL','On_MouseOver','RigthClick','PopUpWindows','Iframe','Label']

    # phising=pd.DataFrame(phis_url,columns=feature_names)
    # print(phising.head(10))
    # print(legitimate.head(10))

    with open('url.txt','r') as fh:
        for l in fh:
            l=l.replace('"','')
            l=l.replace('\n','')
            print(FeatureExtract(l,1))
            print("=======================")
    # url = input("Masukan URL: ")        
    # print(FeatureExtract(url,1))

    # urldataall=pd.concat([legitimate, phising]).reset_index(drop=True)
    # # print(urldataall.sample(n=20))
    # urldataall=urldataall.sample(n=200)
    # urldataall.to_csv('/content/drive/MyDrive/Colab Notebooks/mlskripsi/New-TesData2.csv', index=False)

    # t1 = threading.Thread(target=processdata)
    # t2 = threading.Thread(target=processdata)
    # # t3 = threading.Thread(target=processdata)
    # t1.start()
    # t2.start()
    # # t3.start()
    # t1.join()
    # t2.join()
    # # t3.join()
    timere=time.time() - starttime
    print("Finishing process")
    print("Computing process: ",round(timere,4),"s")