import requests
import time

while True:
    site = input("Insira o link do site:\n")
    
    headers = {
        "accept": "application/json",
        "x-apikey": "db25e36607c89a18a5134ccebbe5223750c99d472789092aa162723920870b5c" #Insira sua ApiKey do VirusTotal aqui
    }
    
    data = {"url": site}
    resposta = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    
    if resposta.status_code != 200:
        print(f"Erro ao enviar URL: {resposta.status_code} - {resposta.text}")
        print(f"Reiniciando...")
        continue
    
    # Obtém o ID da análise retornado pela API após o envio da URL
    id_analise = resposta.json()["data"]["id"]
    print(f"URL enviada para análise. ID: {id_analise}")
    url_reporte = f"https://www.virustotal.com/api/v3/analyses/{id_analise}"
    reporte_resposta = requests.get(url_reporte, headers=headers)
    
    if reporte_resposta.status_code != 200:
        print(f"Erro ao consultar análise: {reporte_resposta.status_code} - {reporte_resposta.text}")
        print(f"Reiniciando...")
        continue
    
    # Processa o resultado da análise obtido através do ID
    reporte = reporte_resposta.json()
    time.sleep(10)
    
    # Extrai as informações relevantes do relatório para facilitar a interpretação
    atributos = reporte.get("data", {}).get("attributes", {})
    status = atributos.get("status", "desconhecido")
    stats = atributos.get("stats", {})
    url_info = reporte.get("meta", {}).get("url_info", {})
    url_analisada = url_info.get("url", "URL desconhecida")
    
    malicioso = stats.get("malicious", 0)
    suspeita = stats.get("suspicious", 0)
    inofensivas = stats.get("harmless", 0)
    nao_detectada = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)
    
    print("\n--- Resultado da Análise ---")
    print(f"""URL analisada: {url_analisada}
Status da análise: {"concluida" if status == "completed" else status} 
Detecções maliciosas: {malicioso}
Detecções suspeitas: {suspeita}
Detecções inofensivas: {inofensivas}
Não detectado: {nao_detectada}
Timeout: {timeout}""")
    
    if malicioso > 0 or suspeita > 0:
        print("⚠️  A URL pode ser perigosa!")
    else:
        print("✅  A URL parece segura.")
    
    novamente = input("Deseja verificar algum outro link\n[1]- Sim\n[2]-Não\n").strip().lower()
    sim = ["1","sim","s"]
    if novamente in sim:
        print("Reiniciando...")
        continue
    else:
        print("Encerrando...")
        break

