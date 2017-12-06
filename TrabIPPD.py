print("[*] Carregando bibliotecas...", end='')
import dropbox
import os
import getpass
import subprocess
import shutil
import sys
import base64
import platform
from termcolor import cprint
from Crypto import Random
from Crypto.Cipher import AES
cprint("OK", "green")

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
	print(
"""
	Exemplos de uso:

	Se um usuário já existente deseja efetuar login
	$ python TrabIPPD.py --login

	Se um novo usuário deseja usar o sistema
	$ python TrabIPPD.py --novousuario <nome do usuario>

	[!] Importante: não é permitido nomes de usuário
					repetidos.
""")

def baixar_lista_usuarios():
	# baixar a lista de usuarios do dropbox
	global dbx

	try:
		dbx.files_download_to_file("usuarios.meta", "/TrabIPPD/metadados/usuarios.meta")
		usuarios = open("usuarios.meta", 'r')
		usuarios_l = usuarios.read().split(';')
		usuarios.close()
		os.remove("usuarios.meta")
		return usuarios_l
	except:
		# Lista de usuarios ainda não existe
		return []
		

def atualizar_lista_usuarios(lista_usuarios_atualizada):
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
	# baixa o arquivo da senha do usuario
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
	resposta = dbx.files_list_folder("/TrabIPPD/" + diretorio)

	try:
		for entry in resposta.entries:
			print("[!] Baixando '" + entry.name + "'...", end='')
			dbx.files_download_to_file(entry.name, "/TrabIPPD/" + diretorio + "/" + entry.name)
			cprint("OK", "green")
		return True
	except:
		cprint("[-] Falha no download dos arquivos.", "white", "on_red")
		return False

def iniciar_sessao(nome):
	if platform.system() == 'Windows':
		cprint("[*] Abrindo PowerShell para {}".format(nome), 'green')
		subprocess.run(["powershell"])
	elif platform.system() == 'Linux' or platform.system() == 'Darwin':
		cprint("[*] Abrindo bash para {}".format(nome), 'green')
		subprocess.run(["bash"])
	else:
		cprint("[-] Plataforma não suportada", "white", "on_red")
		#exit()

def fazer_backup(diretorio):
	print("[*] Fazendo files_uploadad dos arquivos...")
	#após terminar o bash, upa todos os arquivos de volta pro dropbox
	for entry in os.listdir():
		try:
			print("[!] Fazendo o upload de '" + entry + "'...", end='')
			f = open(entry, 'rb')
			dbx.files_upload(f.read(), "/TrabIPPD/" + diretorio + "/"+entry, mode=dropbox.files.WriteMode("overwrite"))
			f.close()
			os.remove(entry)
			cprint("OK", "green")
		except Exception as e:
			cprint("FALHA", "red")
			print()
			cprint("[-] Somente backup de arquivos.", "white", "on_red")

	# feito isso sobe um nível
	cprint("[+] Saindo do diretório...", "green")
	os.chdir("..")

	# e remove o diretório
	os.rmdir(diretorio)

def criar_usuario(nome, usuarios_existentes):
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
			print("upload 1")

			# cria um arquivo padrão a todos os usuários
			dbx.files_upload("Olá".encode(), 
				"/TrabIPPD/{}/README.md".format(nome), 
				mode=dropbox.files.WriteMode("overwrite"))
			print("upload 2")

			os.remove('{}.key'.format(nome))
			usuarios_existentes.append(nome)
			return (True, usuarios_existentes)
		except:
			cprint("[-] Falha na comunicação com o Dropbox.", 'white', 'on_red')
			return (False, usuarios_existentes)
		
def login(nome, senha):
	global dbx
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
			fazer_backup(diretorio)
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

			# atualiza a lista de usuários existente
			atualizar_lista_usuarios(lista_usuarios_atualizada)
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