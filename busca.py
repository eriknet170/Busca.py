import requests
import urllib.parse
import json
import os
from time import sleep
from threading import Thread
import socket
import ssl
from datetime import datetime

# Configurações globais
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
}

TIMEOUT = 15  
MAX_RETRIES = 2  
DELAY_BETWEEN_REQUESTS = 1  
VERBOSE = True  
PROXIES = None  
OUTPUT_FORMAT = 'json'  

# Cores (opcional)
try:
    from colorama import Fore, Style
    verde = Fore.GREEN
    vermelho = Fore.RED
    amarelo = Fore.YELLOW
    azul = Fore.BLUE
    reset = Style.RESET_ALL
except ImportError:
    verde = vermelho = amarelo = azul = reset = ''

def configurar_proxy():
    global PROXIES
    print(f"\n{azul}⚙️ Configuração de Proxy{reset}")
    print("Formato: protocolo://ip:porta (ex: http://127.0.0.1:8080)")
    proxy_input = input("Digite o proxy (deixe em branco para não usar): ").strip()
    if proxy_input:
        PROXIES = {
            'http': proxy_input,
            'https': proxy_input
        }
        print(f"{verde}Proxy configurado com sucesso.{reset}")
    else:
        PROXIES = None
        print(f"{amarelo}Proxy desativado.{reset}")

def verificar_url(url, indicadores_negativos=None, check_redirects=True):
    for _ in range(MAX_RETRIES):
        try:
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=check_redirects,
                verify=True,
                proxies=PROXIES
            )

            # Análise de redirecionamentos suspeitos (honeypots)
            redirect_chain = []
            if response.history:
                for resp in response.history:
                    redirect_chain.append({
                        'url': resp.url,
                        'status_code': resp.status_code,
                        'headers': dict(resp.headers)
                    })

            # Verifica se houve redirecionamento para página genérica
            final_url = response.url.lower()
            if check_redirects and response.url != url:
                if any(x in final_url for x in ['login', 'signin', 'auth', 'security']):
                    if VERBOSE:
                        print(f"{amarelo}[!] Redirecionamento suspeito detectado: {url} → {final_url}{reset}")
                    return False, redirect_chain

            # Verifica status code e conteúdo
            if response.status_code == 404:
                return False, redirect_chain
            if response.status_code == 200:
                conteudo = response.text.lower()
                if indicadores_negativos:
                    for palavra in indicadores_negativos:
                        if palavra in conteudo:
                            return False, redirect_chain
                return True, redirect_chain

        except (requests.exceptions.RequestException, socket.timeout, ssl.SSLError) as e:
            if VERBOSE:
                print(f"{vermelho}Erro ao acessar {url}: {e}{reset}")
            sleep(2)
            continue

    return False, []

def salvar_resultados(dados, tipo_busca, alvo):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"osint_{tipo_busca}_{alvo}_{timestamp}"

    if not os.path.exists('results'):
        os.makedirs('results')

    if OUTPUT_FORMAT == 'json':
        caminho = f"results/{nome_arquivo}.json"
        with open(caminho, 'w', encoding='utf-8') as f:
            json.dump(dados, f, indent=4, ensure_ascii=False)
        print(f"\n{verde}✅ Resultados salvos em {caminho}{reset}")
    else:
        caminho = f"results/{nome_arquivo}.txt"
        with open(caminho, 'w', encoding='utf-8') as f:
            for item in dados:
                f.write(f"{item['site']}: {item['url']} - {'Encontrado' if item['encontrado'] else 'Não encontrado'}\n")
                if item['redirecionamentos']:
                    f.write("  Redirecionamentos:\n")
                    for redir in item['redirecionamentos']:
                        f.write(f"    {redir['url']} ({redir['status_code']})\n")
        print(f"\n{verde}✅ Resultados salvos em {caminho}{reset}")

def buscar_por_usuario(username, usar_threads=False):
    resultados = []
    print(f"\n{azul}🔍 Buscando por nome de usuário: {username}{reset}\n")

    urls = {
        "Instagram": f"https://www.instagram.com/{username}/",
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "Facebook": f"https://www.facebook.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
    }

    indicadores_negativos = [
        "página não encontrada",
        "not found",
        "doesn't exist",
        "page isn't available",
        "404",
    ]

    def verificar_e_imprimir(site, url):
        existe, redirecionamentos = verificar_url(url, indicadores_negativos)
        status = f"{verde}✅ Existe{reset}" if existe else f"{vermelho}❌ Não encontrado{reset}"
        print(f"{amarelo}{site.ljust(12)}{reset} ➜ {status} | {url}")
        
        resultados.append({
            "site": site,
            "url": url,
            "encontrado": existe,
            "redirecionamentos": redirecionamentos
        })
        
        sleep(DELAY_BETWEEN_REQUESTS)

    if usar_threads:
        threads = []
        for site, url in urls.items():
            thread = Thread(target=verificar_e_imprimir, args=(site, url))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
    else:
        for site, url in urls.items():
            verificar_e_imprimir(site, url)

    salvar_resultados(resultados, "usuario", username)

def buscar_por_nome(nome_real):
    resultados = []
    nome = urllib.parse.quote_plus(nome_real)
    print(f"\n{azul}🔍 Buscando por nome real: {nome_real}{reset}\n")

    urls = {
        "Google": f"https://www.google.com/search?q={nome}",
        "LinkedIn": f"https://www.linkedin.com/search/results/people/?keywords={nome}",
        "Facebook": f"https://www.facebook.com/search/people/?q={nome}",
        "Twitter": f"https://twitter.com/search?q={nome}&src=typed_query",
        "Instagram": f"https://www.instagram.com/web/search/topsearch/?context=blended&query={nome}",
    }

    for site, url in urls.items():
        print(f"{amarelo}{site.ljust(12)}{reset} ➜ 🔗 {url}")
        resultados.append({
            "site": site,
            "url": url,
            "encontrado": None,  # Não verificado
            "redirecionamentos": []
        })

    salvar_resultados(resultados, "nome", nome_real)

def buscar_por_email(email):
    resultados = []
    email_encoded = urllib.parse.quote_plus(email)
    print(f"\n{azul}🔍 Buscando por e-mail: {email}{reset}\n")

    urls = {
        "HaveIBeenPwned": f"https://haveibeenpwned.com/unifiedsearch/{email_encoded}",
        "Google": f"https://www.google.com/search?q={email_encoded}",
        "Twitter": f"https://twitter.com/search?q={email_encoded}&src=typed_query",
        "Facebook": f"https://www.facebook.com/search/people/?q={email_encoded}",
        "Gravatar": f"https://en.gravatar.com/{email_encoded}",
    }

    for site, url in urls.items():
        if site == "HaveIBeenPwned":
            try:
                response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, proxies=PROXIES)
                vazado = response.status_code == 200
                status = f"{verde}✅ Vazado{reset}" if vazado else f"{verde}✅ Não vazado{reset}"
                print(f"{amarelo}{site.ljust(16)}{reset} ➜ {status} | {url}")
                
                resultados.append({
                    "site": site,
                    "url": url,
                    "encontrado": vazado,
                    "redirecionamentos": []
                })
            except Exception as e:
                print(f"{amarelo}{site.ljust(16)}{reset} ➜ {vermelho}❌ Erro ao verificar{reset} | {url}")
                resultados.append({
                    "site": site,
                    "url": url,
                    "encontrado": False,
                    "redirecionamentos": []
                })
        else:
            print(f"{amarelo}{site.ljust(16)}{reset} ➜ 🔗 {url}")
            resultados.append({
                "site": site,
                "url": url,
                "encontrado": None,
                "redirecionamentos": []
            })

    salvar_resultados(resultados, "email", email)

def buscar_por_lista(arquivo):
    try:
        with open(arquivo, 'r') as f:
            alvos = [linha.strip() for linha in f.readlines() if linha.strip()]
        
        if not alvos:
            print(f"{vermelho}Arquivo vazio ou formato inválido.{reset}")
            return

        print(f"\n{azul}🔍 Buscando por lista de {len(alvos)} alvos{reset}")
        
        for alvo in alvos:
            if "@" in alvo and "." in alvo:
                buscar_por_email(alvo)
            elif " " in alvo:
                buscar_por_nome(alvo)
            else:
                buscar_por_usuario(alvo)
            print("\n" + "="*50 + "\n")

    except FileNotFoundError:
        print(f"{vermelho}Arquivo não encontrado.{reset}")
    except Exception as e:
        print(f"{vermelho}Erro ao processar arquivo: {e}{reset}")

def configurar_verbose():
    global VERBOSE
    VERBOSE = not VERBOSE
    status = "ATIVADO" if VERBOSE else "DESATIVADO"
    print(f"\n{azul}Modo verbose {status}{reset}")

def configurar_output():
    global OUTPUT_FORMAT
    print(f"\n{azul}⚙️ Formato de Saída Atual: {OUTPUT_FORMAT.upper()}{reset}")
    novo_format = input("Digite o formato desejado (json/txt): ").strip().lower()
    if novo_format in ['json', 'txt']:
        OUTPUT_FORMAT = novo_format
        print(f"{verde}Formato alterado para {OUTPUT_FORMAT.upper()}{reset}")
    else:
        print(f"{vermelho}Formato inválido. Mantendo {OUTPUT_FORMAT.upper()}{reset}")

def menu():
    while True:
        print(f"\n{verde}=== 🕵️ OSINT Tool v4 ==={reset}")
        print("[1] Buscar por nome de usuário")
        print("[2] Buscar por nome real")
        print("[3] Buscar por e-mail")
        print("[4] Buscar por lista de alvos")
        print("[5] Configurar Proxy")
        print("[6] Alternar Modo Verbose")
        print("[7] Configurar Formato de Saída")
        print("[0] Sair")

        escolha = input("\nEscolha uma opção: ").strip()

        if escolha == "1":
            username = input("Digite o nome de usuário: ").strip()
            if username:
                buscar_por_usuario(username, usar_threads=True)
            else:
                print(f"{vermelho}Nome de usuário inválido.{reset}")
        elif escolha == "2":
            nome = input("Digite o nome completo: ").strip()
            if nome:
                buscar_por_nome(nome)
            else:
                print(f"{vermelho}Nome inválido.{reset}")
        elif escolha == "3":
            email = input("Digite o e-mail: ").strip()
            if "@" in email and "." in email:
                buscar_por_email(email)
            else:
                print(f"{vermelho}E-mail inválido.{reset}")
        elif escolha == "4":
            arquivo = input("Digite o caminho do arquivo com a lista: ").strip()
            buscar_por_lista(arquivo)
        elif escolha == "5":
            configurar_proxy()
        elif escolha == "6":
            configurar_verbose()
        elif escolha == "7":
            configurar_output()
        elif escolha == "0":
            print("Saindo...")
            break
        else:
            print(f"{vermelho}Opção inválida.{reset}")

if __name__ == "__main__":
    menu()
