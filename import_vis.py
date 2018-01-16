import argparse
import os

from neo4j.v1 import GraphDatabase, basic_auth
import pefile

def get_imports(pe):
	dll_imports = {}
	all_funcs = []
	if pe.DIRECTORY_ENTRY_IMPORT:
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			dll_imports[entry.dll] = []
			for item in entry.imports:
				if item.name:
					dll_imports[entry.dll].append(item.name)
					all_funcs.append(item.name)
	return dll_imports, all_funcs
	
def connect_db(username, password, url):
	driver = GraphDatabase.driver(url, auth=basic_auth(username, password))
	session = driver.session()
	return driver, session
	
def get_file_paths(search_root):
	targets = set(['dll', 'exe'])

	binaries = []
	for path, subdirs, files in os.walk(search_root):
		for name in files:
			full_path = os.path.join(path, name)
			if '.' in name:
				extension = name.split('.')[-1]
				if extension in targets:
					binaries.append(full_path)
	return binaries

def load_file(path, db, created_dlls):
	pe =  pefile.PE(path)
	if pe.is_dll():
		process_dll(pe, path, db, created_dlls)
	elif pe.is_exe():
		process_exe(pe, path, db, created_dlls)
	elif pe.is_driver():
		process_driver(pe, path, db, created_dlls)
	else:
		print("Couldn't work out what {} is.".format(path))
		
def process_dll(pe, path, db, created_dlls):
	print("Processing dll: {}".format(path))
	dll_imports, all_funcs = get_imports(pe)
	root_path, name = os.path.split(path)
	with db.begin_transaction() as tx:
		tx.run(
			"MERGE (bin: DLL {name: $name, path: $path, imports: $imports})",
			name=name, path=path, imports=all_funcs
		)
	for dll in dll_imports.keys():
		if dll not in created_dlls:
			create_stub_dll(dll, db)
		with db.begin_transaction() as tx:
			tx.run(
				"MATCH (main_dll: DLL) WHERE main_dll.name ={main_dll}\
				MATCH (dll: DLL) WHERE dll.name ={dll_name}\
				CREATE ((main_dll)-[:IMPORTS {functions: $functions}]->(dll))",
				functions=dll_imports[dll], main_dll=name, dll_name=dll
			)

def process_exe(pe, path, db, created_dlls):
	print("Processing exe")
	dll_imports, all_funcs = get_imports(pe)

	root_path, name = os.path.split(path)
	with db.begin_transaction() as tx:
		tx.run(
			"MERGE (bin: EXE {name: $name, path: $path, imports: $imports})",
			name=name, path=path, imports=all_funcs
		)
	for dll in dll_imports.keys():
		if dll not in created_dlls:
			create_stub_dll(dll, db)
		with db.begin_transaction() as tx:
			tx.run(
				"MATCH (exe: EXE) WHERE exe.name ={exe}\
				MATCH (dll: DLL) WHERE dll.name ={dll_name}\
				CREATE ((exe)-[:IMPORTS {functions: $functions}]->(dll))",
				functions=dll_imports[dll], exe=name, dll_name=dll
			)

def process_driver(pe, path, db, created_dlls):
	print("processing driver")
	dll_imports, all_funcs = get_imports(pe)

	root_path, name = os.path.split(path)
	with db.begin_transaction() as tx:
		tx.run(
			"MERGE (bin: Driver {name: $name, path: $path, imports: $imports})",
			name=name, path=path, imports=all_funcs
		)
	for dll in dll_imports.keys():
		if dll not in created_dlls:
			create_stub_dll(dll, db)
		with db.begin_transaction() as tx:
			tx.run(
				"MATCH (driver: Driver) WHERE driver.name ={driver}\
				MATCH (dll: DLL) WHERE dll.name ={dll_name}\
				CREATE ((driver)-[:IMPORTS {functions: $functions}]->(dll))",
				functions=dll_imports[dll], driver=name, dll_name=dll
			)


def create_stub_dll(name, db):
	print("Created stub dll: {}".format(name))
	with db.begin_transaction() as tx:
		tx.run(
			"MERGE (bin: DLL {name: $name})",
			name=name
		)

def create_dll(path, db):
	pe =  pefile.PE(path)
	exports = []
	if pe.DIRECTORY_ENTRY_EXPORT:
			for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
				exports.append(export.name)
	root_path, name = os.path.split(path)
	with db.begin_transaction() as tx:
		tx.run(
			"MERGE (bin: DLL {name: $name, path: $path, exports: $exports})",
			name=name, path=path, exports=exports
		)
	
def load_all(paths, created_dlls, db):
	for path in paths:
		load_file(path, db, created_dlls)
	print("All files loaded.")
	
def create_dlls(paths, db):
	created = set()
	print("Creating all dlls with exports")
	for path in paths:
		if path.endswith('dll'):
			root_path, name = os.path.split(path)
			create_dll(path, db)
			created.add(name)
	print("All dlls created.")
	return created
	
def main():
	parser = argparse.ArgumentParser(
		description='Loads imports and exports from PE files in a given directory into Neo4j for querying and analysis.'
	)
	parser.add_argument('--root', '-r', metavar='path',
		help="Folder to index DLL's from", required=True)
	parser.add_argument('--username', '-u', metavar='username',
		help="Neo4j username", required=False, default='neo4j')
	parser.add_argument('--password', '-p', metavar='password',
		help="Neo4j password", required=False, default='neo4j')
	parser.add_argument('--address','-a', metavar='address', 
		help="URL and port for connecting to Neo4j", required=False, default='bolt://localhost:7687')
	args = parser.parse_args()
	search = args.root
	targets = get_file_paths(search)
	print("Identified {} target binaries.".format(len(targets)))
	driver, db = connect_db(args.username, args.password, args.address)
	created = create_dlls(targets, db)
	load_all(targets, created, db)
	db.close()

if __name__ == "__main__":
	main()