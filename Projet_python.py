import feedparser 
import requests 
import pandas as pd
import time 
#%% Etape 1:
    
#Exploration des url 
url_alerte = "https://www.cert.ssi.gouv.fr/alerte/feed/" 
url_avis = "https://www.cert.ssi.gouv.fr/avis/feed/"

rss_feed_alerte = feedparser.parse(url_alerte) 
rss_feed_avis = feedparser.parse(url_avis) 


#%% Etape 2 : 


def ajouter_temporisateur():
    time.sleep(0.5)  #prend une pause de 0.5 seconde 
    
    
#Extraction des CVE des alertes 
CVE_référencés_alerte = []
for entry in rss_feed_alerte.entries: 
    url_alerte_CVE = str(entry.link) + "/json/"
    response = requests.get(url_alerte_CVE) 
    data_alerte = response.json() 
    #Extraction des CVE reference dans la clé cves du dict data 
    ref_cves=list(data_alerte["cves"])
    for cves in ref_cves:
        cves["Titre du bulletin (ANSSI)"] = entry.title
        cves["Date de publication"] = entry.published
        cves["Lien du bulletin (ANSSI)"] = entry.link
    CVE_référencés_alerte += ref_cves     
    
#Extraction des CVE des avis
CVE_référencés_avis = []
for entry in rss_feed_avis.entries: 
    url_avis_CVE = str(entry.link) + "/json/"
    response = requests.get(url_avis_CVE) 
    data_avis = response.json() 
    #Extraction des CVE reference dans la clé cves du dict data 
    ref_cves=list(data_avis["cves"])
    for cves in ref_cves:
        cves["Titre du bulletin (ANSSI)"] = entry.title
        cves["Date de publication"] = entry.published
        cves["Lien du bulletin (ANSSI)"] = entry.link
    CVE_référencés_avis += ref_cves

#%% Etape 3 :
    
#Extraction de données pour alerte
for cve_alerte in CVE_référencés_alerte:
    cve_id = cve_alerte['name']   
    
    #Création de l'url pour les api
    url_alerte_api = f"https://cveawg.mitre.org/api/cve/{cve_id}" 
    response = requests.get(url_alerte_api) 
    ajouter_temporisateur()
    data_api = response.json() 
    
    #Création de l'url pour récupérer l'epss
    url_alerte_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    response = requests.get(url_alerte_epss) 
    ajouter_temporisateur()
    data_epss = response.json() 
    
    # Extraire la description  
    description = data_api["containers"]["cna"]["descriptions"][0]["value"]  
    
    # Extraire le score CVSS  
    
    # Si cvss est dans cna
    metric = data_api["containers"]["cna"].get("metrics", [])
    cvss_score = "Non disponible"
    for met in metric:
        # Recherche du score cvss 
        if "cvssV4_0" in  met.keys(): 
            cvss_score = met["cvssV4_0"].get("baseScore", "Non disponible")
        elif "cvssV4_1" in met.keys():
            cvss_score = met["cvssV4_1"].get("baseScore", "Non disponible")
        elif "cvssV3_0" in met.keys():
            cvss_score = met["cvssV3_0"].get("baseScore", "Non disponible")
        elif "cvssV3_1" in met.keys():
             cvss_score = met["cvssV3_1"].get("baseScore", "Non disponible")
             
    #Si cvss est dans adp
    adp = data_api["containers"].get("adp", [])
    if metric == []:
        try:
            metric = adp[0].get("metrics",[])
        except:
            metric = []
    if metric != []:
        if "cvssV4_0" in  metric[0].keys(): 
            cvss_score = metric[0]["cvssV4_0"].get("baseScore", "Non disponible")
        elif "cvssV4_1" in metric[0].keys():
            cvss_score = metric[0]["cvssV4_1"].get("baseScore", "Non disponible")
        elif "cvssV3_0" in metric[0].keys():
            cvss_score = metric[0]["cvssV3_0"].get("baseScore", "Non disponible")
        elif "cvssV3_1" in metric[0].keys():
             cvss_score = metric[0]["cvssV3_1"].get("baseScore", "Non disponible")
             
    #Extraction de CWE et de sa description
    # Initialisation de cwe et cwe_desc
    cwe = "Non disponible" 
    cwe_desc="Non disponible" 
    cna = data_api["containers"]["cna"]     
    problemtype = cna.get("problemTypes", {}) 
    if problemtype and "descriptions" in problemtype[0]: 
        #Extraction de CWE
        cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible") 
        #Extraction de CWE et de sa description
        cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible") 
    # Si cwe  et description dans apd
    if cwe == "Non disponible" :
        try:
            cwe = adp[0]["problemTypes"][0]["descrption"][0]["cweId"]
        except:
            cwe = cwe
    
    if  cwe_desc=="Non disponible":
        try:
            cwe_desc = adp[0]["problemTypes"][0]["descrption"][0]["description"]
        except:
            cwe_desc = cwe_desc
   
    # Extraire les produits affectés  
    affected = data_api["containers"]["cna"]["affected"] 
    for product in affected: 
        #Extraction de vendor
        vendor = product.get("vendor", "Non disponible")
        #Extraction de product
        product_name = product.get("product", "Non disponible")
        #Extraction des versions affectées
        versions = [v.get("version", "Non disponible") for v in product.get("versions",{}) if v["status"] == "affected"] 
        print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}") 
        
    
    # Afficher les résultats  
    print(f"CVE : {cve_id}")  
    print(f"Description : {description}")  
    print(f"Score CVSS : {cvss_score}") 
    print(f"Type CWE : {cwe}") 
    print(f"CWE Description : {cwe_desc}") 
    
    # Extraire le score EPSS 
    epss_data = data_epss.get("data", []) 
    epss_score = "Non disponible"
    if epss_data: 
        epss_score = epss_data[0]["epss"] 
        print(f"CVE : {cve_id}") 
        print(f"Score EPSS : {epss_score}") 
    else: 
        print(f"Aucun score EPSS trouvé pour {cve_id}")

    
   
    cve_alerte["Type de bulletin"] = "alerte"
    cve_alerte["Identifiant CVE"] = cve_id
    if cvss_score != "Non disponible":
        cve_alerte["Score CVSS"] = float(cvss_score)
    else:
        cve_alerte["Score CVSS"] = cvss_score
        
    # Création de la liste de d'indice de gravité de la vulnérabilité
    # Initialisation par défaut
    cve_alerte["Base severity"] = "Non disponible"

# Vérification si cvss_score est un nombre valide
    if isinstance(cvss_score, (float, int)):  # Vérifie si cvss_score est un nombre
        if 0.0 <= cvss_score <= 3.9:  # 0 à 3.9 inclus
            cve_alerte["Base severity"] = "Faible"
        elif 4.0 <= cvss_score <= 6.9:  # 4 à 6.9 inclus
            cve_alerte["Base severity"] = "Moyenne"
        elif 7.0 <= cvss_score <= 8.9:  # 7 à 8.9 inclus
            cve_alerte["Base severity"] = "Elevée"
        elif 9.0 <= cvss_score <= 10.0:  # 9 à 10 inclus
            cve_alerte["Base severity"] = "Critique"
                    
    
    cve_alerte["Score Epss"] = epss_score
    cve_alerte["Type CWE"] = cwe
    cve_alerte["Description CWE"] = cwe_desc
    cve_alerte["Editeur"]=vendor
    cve_alerte["Produit"]=product_name
    cve_alerte["Versions affectées "]=versions 

for i in CVE_référencés_alerte:
        del i["name"]
        del i['url']
#%% Etape 3 :

#Extraction de données pour avis
for cve_avis in CVE_référencés_avis:
    cve_id = cve_avis['name']   
    url_avis_api = f"https://cveawg.mitre.org/api/cve/{cve_id}" 
    url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    response = requests.get(url_avis_api) 
    data_api = response.json() 
    response = requests.get(url_epss) 
    data_epss = response.json() 
    
    # Extraire la description 
    if "containers" in data_api.keys() and "descriptions" in data_api["containers"]["cna"] :
        
        description = data_api["containers"]["cna"]["descriptions"][0]["value"]  
        # Extraire le score CVSS  
    #ATTENTION tous les CVE ne contiennent pas necéssairement ce champ, gérez l’exception,  
    #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé 
    
        # Extraction du tableau metrics  si il existe
        metric = data_api["containers"]["cna"].get("metrics", [])    
        if metric == [] and "metrics" in data_api["containers"].get("adp",[]):
            metric = data_api["containers"]["adp"][0]
        cvss_score = "Non disponible"
        for met in metric:
            if "cvssV4_0" in  met.keys():
                cvss_score = met["cvssV4_0"].get("baseScore", "Non disponible")
            elif "cvssV4_1" in met.keys():
                cvss_score = met["cvssV4_1"].get("baseScore", "Non disponible")
            elif "cvssV3_0" in met.keys():
                cvss_score = met["cvssV3_0"].get("baseScore", "Non disponible")
            elif "cvssV3_1" in met.keys():
                 cvss_score = met["cvssV3_1"].get("baseScore", "Non disponible")
            
        # Si cvss est dans adp
        adp = data_api["containers"].get("adp", [])
        if metric == []:
            try:
                metric = adp[0].get("metrics",[])
            except:
                metric = []
        if metric != []:
            if "cvssV4_0" in  metric[0].keys(): 
                cvss_score = metric[0]["cvssV4_0"].get("baseScore", "Non disponible")
            elif "cvssV4_1" in metric[0].keys():
                cvss_score = metric[0]["cvssV4_1"].get("baseScore", "Non disponible")
            elif "cvssV3_0" in metric[0].keys():
                cvss_score = metric[0]["cvssV3_0"].get("baseScore", "Non disponible")
            elif "cvssV3_1" in metric[0].keys():
                 cvss_score = metric[0]["cvssV3_1"].get("baseScore", "Non disponible")
    
        # Extraction de CWE 
        cwe = "Non disponible" 
        cwe_desc="Non disponible" 
        cna = data_api["containers"]["cna"]
        
        # Si cwe et description sont  dans cna
        problemtype = cna.get("problemTypes", {}) 
        if problemtype and "descriptions" in problemtype[0]: 
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible") 
            cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible") 
            if cwe == "Non disponible" :
                try:
                    cwe = adp[0]["problemTypes"][0]["descrption"][0]["cweId"]
                except:
                    cwe = cwe 
                    
        # Si cwe  et description  sont dans apd
        if  cwe_desc=="Non disponible":
            try:
                cwe_desc = adp[0]["problemTypes"][0]["descrption"][0]["description"]
            except:
                cwe_desc = cwe_desc
        
        # Extraire les produits affectés  
        affected = data_api["containers"]["cna"]["affected"] 
        for product in affected: 
            vendor = product.get("vendor", "Non disponible")
            product_name = product.get("product", "Non disponible")
            versions = [v.get("version", "Non disponible") for v in product.get("versions",{}) if v["status"] == "affected"] 
            print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}") 
        # Afficher les résultats  
        print(f"CVE : {cve_id}")  
        print(f"Description : {description}")  
        print(f"Score CVSS : {cvss_score}") 
        print(f"Type CWE : {cwe}") 
        print(f"CWE Description : {cwe_desc}") 
        
        # Extraire le score EPSS 
        epss_data = data_epss.get("data", []) 
        if epss_data: 
            epss_score = epss_data[0]["epss"] 
            print(f"CVE : {cve_id}") 
            print(f"Score EPSS : {epss_score}") 
        else: 
            print(f"Aucun score EPSS trouvé pour {cve_id}")
            
        
       
        cve_avis["Type de bulletin"] = "avis"
        cve_avis["Identifiant CVE"] = cve_id
        cve_avis["Score CVSS"] = cvss_score
        cve_avis["Score Epss"] = epss_score
        
        # Création de la liste de d'indice de gravité de la vulnérabilité
        cve_avis["Base severity"] = "Non disponible"
        if cvss_score != "Non disponible":
            if 0.0 <= cvss_score and 3.0 >= cvss_score:
                cve_alerte["Base severity"] = "Faible"
            elif 4.0 <= cvss_score and 6.0 >= cvss_score:
                cve_alerte["Base severity"] = "Moyenne"
            elif 7.0 <= cvss_score and 8.0 >= cvss_score:
                cve_alerte["Base severity"] = "Elevée"     
            elif 9.0 <= cvss_score and 10.0 >= cvss_score:
                cve_alerte["Base severity"] = "Critique"
            
        cve_avis["Type CWE"] = cwe
        cve_avis["Description CWE"] = cwe_desc
        cve_avis["Editeur"]=vendor
        cve_avis["Produit"]=product_name
        cve_avis["Versions affectées "]=versions 
    
for i in CVE_référencés_avis:
        del i["name"]
        del i['url']

        
#%% étape 4

df_alerte = pd.DataFrame(CVE_référencés_alerte)
df_avis = pd.DataFrame(CVE_référencés_avis) 
#Fusion des dico alertes et avis

# Concaténation verticale (empiler les DataFrames)
df = pd.concat([df_alerte, df_avis], ignore_index=True)
df['Date de publication'] = df['Date de publication'].combine_first(df['Date de publication'])
df = df.drop(columns=['Date de publication', 'Date de publication'])

# Afficher les résultats
print(df)
df.to_csv('consolidation_des_données.csv', index=False)  


#%% étape 5 : Voir graphiques et interprétations sur Jupyter

#%% étape 6

import smtplib 
from email.mime.text import MIMEText 
CVE_critiques=[]
for x in CVE_référencés_alerte:
    if x["Base severity"]== "Critique" :
        CVE_critiques.append(x["Identifiant CVE"])
CVE_critiques_str = "\n".join(CVE_critiques)
        
def send_email(to_email, subject, body): 
    from_email = "Anonyme2272004@gmail.com" 
    password = "yesn flwl flat kkyi " 
    msg = MIMEText(body) 
    msg['From'] = from_email 
    msg['To'] = to_email 
    msg['Subject'] = subject 
    server = smtplib.SMTP('smtp.gmail.com', 587) 
    server.starttls() 
    server.login(from_email, password) 
    server.sendmail(from_email, to_email, msg.as_string()) 
    server.quit() 
send_email("Anonyme2272004@gmail.com", "Alerte CVE critiques", f"27  CVE ont été detectées qui sont: \n{CVE_critiques_str}.")


