# Consolidation et Analyse des Vulnérabilités à partir des Bulletins ANSSI

Ce programme automatise l'extraction, l'analyse et la consolidation des vulnérabilités  référencées dans les bulletins ANSSI (alertes et avis). Il enrichit ces données avec des informations externes issues des API telles que MITRE CVE et EPSS. 

# 1. Bibliothèques Python nécessaires 

 ```
  import feedparser 
  import requests 
  import pandas 
  import seaborn 
 ```

# 2. Flux RSS utilisés 
 
 -Alertes ANSSI : https://www.cert.ssi.gouv.fr/alerte/feed/ 

 -Avis ANSSI : https://www.cert.ssi.gouv.fr/avis/feed/ 
 

# 3. Fonctionnalités 
 ## 1.a.Extraction des données des flux RSS de l’ANSSI 
  Les flux RSS des alertes et des avis sont lus depuis leurs    URLs respectives. 

 ### Exemple de flux utilisé :
 ```
 url_alerte = "https://www.cert.ssi.gouv.fr/alerte/feed/" 
 rss_feed_alerte = feedparser.parse(url_alerte) 
 ```

 ## 1.b.Récupération des données RSS 
 Les flux sont lus à l’aide de feedparser pour extraire les    alertes et les avis. Les CVE y sont identifiés et extraits.

 ### Exemple :
 ```
 for entry in rss_feed_alerte.entries: 
    url_alerte_CVE = str(entry.link) + "/json/" 
    response = requests.get(url_alerte_CVE)
    data_alerte = response.json() 
    ref_cves = list(data_alerte["cves"])
 ```

 ## 2.a.Enrichissement des données de vulnérabilités

 Pour chaque CVE trouvé, le programme récupère :  
 -Une description détaillée via l’API MITRE CVE.
 -Le score CVSS (s’il existe) pour évaluer la gravité. 
 -Le score EPSS pour estimer la probabilité d’exploitation.

 ### Exemple d’appel API pour récupérer les détails 
 ```
 url_alerte_api = f"https://cveawg.mitre.org/api/cve/{cve_id}" 
 response = requests.get(url_alerte_api) 
 data_api = response.json() 
  ```

 ## 2.b.Enrichissement des CVE 
  Chaque CVE est enrichi avec des données supplémentaires obtenues via les APIs : 

 ### Description 
 `
  description = data_api["containers"]["cna"][  "descriptions"][0]["value"] 
  `
 ### Score CVSS (avec gestion des différentes versions) 
 ```
 if"cvssV3_1" in metric[0].keys(): 
    cvss_score = metric[0]["cvssV3_1"].get("baseScore", "Non    disponible") 
  ```
 ### Score EPSS 
 ```
 url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"  response = requests.get(url_epss) 
 data_epss = response.json() 
 epss_score = data_epss.get("data", [])[0]["epss"] 
  ```

# 4.Analyse et catégorisation 
 Les vulnérabilités sont classées en fonction de leur gravité   (faible, moyenne, élevée, critique) selon le score CVSS.  

 ### Exemple de catégorisation
 ```
 if 0.0 <= cvss_score <= 3.9: 
    cve_alerte["Base severity"] = "Faible" 
 elif 4.0 <= cvss_score <= 6.9: 
    cve_alerte["Base severity"] = "Moyenne" 
 elif 7.0 <= cvss_score <= 8.9: 
    cve_alerte["Base severity"] = "Elevée" 
 elif 9.0 <= cvss_score <= 10.0: 
    cve_alerte["Base severity"] = "Critique" 
 ```
 
# 5.Fusion et export des données 
 Les données des alertes et avis sont fusionnées dans un   tableau unique pour faciliter l’analyse. Le tableau est ensuite exporté en format CSV. 

 ### Exemple de fusion 
 ```
 df_alerte = pd.DataFrame(CVE_référencés_alerte) 
 df_avis = pd.DataFrame(CVE_référencés_avis) 
 df = pd.concat([df_alerte, df_avis], ignore_index=True) 
 df.to_csv('consolidation_des_données.csv', index=False)
 ```
 ![](https://imgur.com/rjPv2Mj.jpeg)

# 6.Résultats 
  Fichier de sortie : consolidation_des_données.csv  
 Contenu :   
  -Titre du bulletin (ANSSI)  
  -Identifiant CVE  
  -Score CVSS et catégorie (faible, moyenne, élevée, critique)  
  -Score EPSS  
  -Description du CWE et produits affectés 

 #### Extrait du  fichier csv 
![](https://imgur.com/ja0jmpk.jpeg)

# 7.  Notification  e-mail pour les CVE critiques
 Le programme permet d'envoyer une alerte par e-mail pour notifier les CVE critiques   détectées. Les CVE critiques sont identifiées, formatées, et incluses dans un e-mail envoyé via SMTP.

Les CVE critiques sont extraites et affichées une par ligne grâce à "\n".join().

#### Exemple
 ```
 CVE_critiques=[]
for x in CVE_référencés_alerte:
    if x["Base severity"]== "Critique" :
        CVE_critiques.append(x["Identifiant CVE"] 
CVE_critiques_str = "\n".join(CVE_critiques)
```
un mail a été  envoyé à l'utilisateur Anonyme2272004@gmail.com avec le message suivant :
```
  "27  CVE ont été detectées qui sont: {CVE_critiques_str}."
 ```
 ![](https://imgur.com/uUNhA5A.jpeg)
# 8.Améliorations futures 


-Ajouter un système de visualisation des vulnérabilités avec  seaborn.  
 -Intégrer d'autres sources pour enrichir les données des CVE. 
 


