import dropbox
import os
import getpass
import subprocess
import shutil
import sys
import base64
import platform
import colorama
from hurry.filesize import size
from termcolor import cprint
from Crypto import Random
from Crypto.Cipher import AES

colorama.init(autoreset=True)

dbx = dropbox.Dropbox("D-O1ZZNk_DAAAAAAAAAACInxO5rjy5hAKQzSidx2FIQF-FyoexAvamvvJiqNWX-H")

# ------------ FUNÇÕES DE CRIPTOGRAFIA ------------
BLOCK_SIZE=16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def encrypt(mensagem, senha):
	mensagem = pad(mensagem)
	iv = Random.new().read( AES.block_size )
	cipher = AES.new(senha, AES.MODE_CBC, iv )
	return base64.b64encode(iv + cipher.encrypt(mensagem))

def decrypt(mensagem, senha):
	enc = base64.b64decode(mensagem)
	iv = enc[:16]
	cipher = AES.new(senha, AES.MODE_CBC, iv)
	return unpad(cipher.decrypt( enc[16:]))

# ------------ FUNÇÕES DE CRIPTOGRAFIA ------------

def print_ajuda():
	print("""
	Exemplos de uso:

	Se um usuário já existente deseja efetuar login
	$ python TrabIPPD.py --login

	Se um novo usuário deseja usar o sistema
	$ python TrabIPPD.py --novousuario <nome do usuario>

	[!] Importante: não é permitido nomes de usuário
					repetidos.""")

def baixar_lista_usuarios():
	"""Baixa a lista de usuários (usuarios.meta) na a máquina host para extrair
	a lista de usuários cadastrados"""
	global dbx

	try:
		# faz o download do arquivo do dropbox para o arquivo
		dbx.files_download_to_file("usuarios.meta", 
			"/TrabIPPD/metadados/usuarios.meta")
		usuarios = open("usuarios.meta", 'r')
		usuarios_l = usuarios.read().split(';')
		usuarios.close()
		os.remove("usuarios.meta")
		return usuarios_l
	except:
		# Lista de usuarios ainda não existe
		return []
		
def atualizar_lista_usuarios(lista_usuarios_atualizada):
	"""Atualiza a lista de usuários no arquivo de metadados no computador 
	host e sincroniza com o Dropbox"""
	global dbx

	usuarios = open("usuarios.meta", 'w')
	usuarios_atualizada = ";".join(lista_usuarios_atualizada)
	usuarios.write(usuarios_atualizada)
	usuarios.close()
	usuarios = open("usuarios.meta", 'rb')

	try:
		dbx.files_upload(usuarios.read(), 
			"/TrabIPPD/metadados/usuarios.meta", 
			mode=dropbox.files.WriteMode("overwrite"))
		usuarios.close()
		os.remove("usuarios.meta")
		return True
	except:
		usuarios.close()
		os.remove("usuarios.meta")
		cprint("[-] Falha na comunicação com o Dropbox.", 'white', 'on_red')
		return False

def baixar_arquivo_senha_usuario(nome):
	"""Baixa o arquivo da senha do usuario"""
	try:
		fonte = "/TrabIPPD/metadados/{}.key".format(nome)
		dbx.files_download_to_file("{}.key".format(nome), fonte)
		return True
	except:
		cprint("[-] Falha na comunicação com o Dropbox.", 'white', 'on_red')
		return False

def baixar_arquivos(diretorio):
	global dbx
	# parte responsável por listar os arquivos e fazer o download para uma pasta local
	diretorio_dbx = dbx.files_list_folder("/TrabIPPD/" + diretorio)

	try:
		for arquivo in diretorio_dbx.entries:
			print("[!] Baixando '" + arquivo.name + "'...", end='')
			dbx.files_download_to_file(arquivo.name, 
				"/TrabIPPD/" + diretorio + "/" + arquivo.name)
			cprint("OK", "green")
		return True
	except Exception as e:
		cprint("[-] Falha no download dos arquivos.", "white", "on_red")
		print(e)
		return False

def iniciar_sessao(nome):
	"""Abre um shell de sessão para o usuário, enquanto esse shell estiver ativo,
	quando esse shell terminar, os arquivos na máquina do usuário serão sincronizados
	com a pasta do usuário no dropbox"""
	if platform.system() == 'Windows':
		cprint("[*] Abrindo PowerShell para {}".format(nome), 'green')
		subprocess.run(["powershell"])
	elif platform.system() == 'Linux' or platform.system() == 'Darwin':
		cprint("[*] Abrindo bash para {}".format(nome), 'green')
		subprocess.run(["bash"])
	else:
		cprint("[-] Plataforma não suportada", "white", "on_red")


def calcular_deltas(diretorio):
	global dbx
	diretorio_dbx = dbx.files_list_folder("/TrabIPPD/" + diretorio).entries

	diretorio_dbx = [arq.name for arq in diretorio_dbx]
	diretorio_host = os.listdir()

	# calcula a diferença entre os itens no dropbox e os arquivos no host
	delta = list(set(diretorio_dbx) - set(diretorio_host))
	return delta

def fazer_backup(nome, diretorio):
	"""Envia todos os arquivos no diretório atual para a pasta do usário"""
	total = sum(os.path.getsize(f) for f in os.listdir('.') if os.path.isfile(f))

	print("Total de {}".format(size(total)))

	print("[*] Consultando Dropbox sobre o espaço disponível... ", end='')
	resp = dbx.users_get_space_usage()
	livre = resp.allocation.get_individual().allocated - resp.used
	print("Espaço disponível: {}".format(size(livre)))

	if livre > total:
		# calcula a diferença entre os arquivos no host e os arquivos no dropbox
		delta = calcular_deltas(diretorio)

		# faz o backup de todos os arquivos que estão no host
		print("[*] Fazendo upload dos arquivos...")
		for arquivo in os.listdir():
			try:
				print("[!] Fazendo o upload de '" + arquivo + "'...", end='')
				f = open(arquivo, 'rb')
				dbx.files_upload(f.read(), "/TrabIPPD/" + diretorio + "/"+arquivo, mode=dropbox.files.WriteMode("overwrite"))
				f.close()
				os.remove(arquivo)
				cprint("OK", "green")
			except Exception as e:
				cprint("FALHA", "red")
				print()
				cprint("[-] Somente backup de arquivos.", "white", "on_red")

		# remove do dropbox todos os arquivos que não estavam no host
		print("[!] Resolvendo diferenças...", end='')
		for arq in delta:
			dbx.files_delete("/TrabIPPD/" + diretorio + "/" + arq)

		cprint("OK", 'green')

		# sobe para a pasta acima
		cprint("[+] Saindo do diretório...", "green")
		os.chdir("..")

		# remove o diretório
		os.rmdir(diretorio)
	else:
		cprint("[-] Não há espaço disponível no Dropbox para fazer o backup de arquivos.", 'white', 'on_red')
		print("[*] Tente novamente em uma nova sessão.")
		iniciar_sessao(nome)
		fazer_backup(nome, diretorio)



def criar_usuario(nome, usuarios_existentes):
	"""Cria um novo usuário no sistema dado o nome do novo usuário e a lista de 
	usuários existentes"""
	global dbx
	if nome in usuarios_existentes:
		cprint("[-] Usuário já existe.", 'white', 'on_red')
		return (False, usuarios_existentes)
	else:
		senha = getpass.getpass("[*] Senha: ")
		senha_crip = encrypt(senha, pad(senha))
		arq_usuario = open('{}.key'.format(nome), 'w')
		arq_usuario.write(senha_crip.decode())
		arq_usuario.close()
		
		# faz upload
		try:
			# cria um arquivo com a senha criptografada
			dbx.files_upload(senha_crip, 
				"/TrabIPPD/metadados/{}.key".format(nome), 
				mode=dropbox.files.WriteMode("overwrite"))

			# cria um arquivo padrão a todos os usuários
			dbx.files_upload("Olá".encode(), 
				"/TrabIPPD/{}/README.md".format(nome), 
				mode=dropbox.files.WriteMode("overwrite"))

			os.remove('{}.key'.format(nome))
			usuarios_existentes.append(nome)
			return (True, usuarios_existentes)
		except:
			cprint("[-] Falha na comunicação com o Dropbox.", 'white', 'on_red')
			return (False, usuarios_existentes)
		
def login(nome, senha):
	"""Mecanismo que efetua o login no do usuário no sistema"""
	global dbx
	# baixa a lista de usuário do dropbox
	lista_usuarios = baixar_lista_usuarios()

	if nome in lista_usuarios:
		if baixar_arquivo_senha_usuario(nome):
			arq = open("{}.key".format(nome), 'r')
			conteudo = arq.read()
			conteudo_dec = decrypt(conteudo, pad(senha))

			# compara se a senha passada é a mesma senha do usuário
			if conteudo_dec.decode() == senha:
				arq.close()
				os.remove("{}.key".format(nome))
				return True
			else:
				arq.close()
				os.remove("{}.key".format(nome))
				cprint("[-] Senha incorreta.", 'white', 'on_red')
				return False
		else:
			exit()
	else:
		print()
		cprint("[-] Usuário não existe.", 'white', 'on_red')
		exit()

def sessao():
	"""Controla a sessão do usuário"""
	global dbx

	nome = input("[?] Entre com o usuário: ")
	senha = getpass.getpass('[?] Entre com a senha: ')

	print("[!] Conectando com o Dropbox...", end='')

	if login(nome, senha):
		cprint("OK", "green")
		diretorio = nome

		# cria diretório
		if not os.path.exists(diretorio):
			os.mkdir(diretorio)

		# entra no díretório
		os.chdir(diretorio)

		if baixar_arquivos(diretorio):
			iniciar_sessao(nome)
			fazer_backup(nome, diretorio)
		else:
			sn = str(input('[!] Deseja tentar novamente? [s, n] '))
			if sn == 's':
				sessao()
			else:
				exit()

	else:
		cprint("[-] Falha ao fazer login.", "white", "on_red")
		sessao()

if __name__ == "__main__":
	args = sys.argv
	if len(args) == 3:
		if args[1] == '--novousuario':
			nome = args[2]
			# baixa a lista de usuários existente
			lista_usuarios = baixar_lista_usuarios()

			# cria o novo usuário
			stat, lista_usuarios_atualizada = criar_usuario(nome, lista_usuarios)

			if stat:
				# atualiza a lista de usuários existente
				atualizar_lista_usuarios(lista_usuarios_atualizada)
			else:
				exit()
		else:
			cprint("[-] Comando não identificado.", "white", "on_red")
			print_ajuda()
	elif len(args) == 2:
		if args[1] == '--login':
			# inicia a sessão do usuário
			sessao()
		else:
			cprint("[-] Comando não identificado.", "white", "on_red")
			print_ajuda()
	else:
		print_ajuda()