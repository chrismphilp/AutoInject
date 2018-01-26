import pymongo, re, time, datetime, os

# Parsing related modules
import ply.lex      as lex

from pymongo        import MongoClient
from json           import loads
from bson.json_util import dumps

from subprocess     import check_output, check_call
from copy           import copy
from collections    import defaultdict

client                      = MongoClient()
package_collection          = client['package_db']['package_list']
cve_collection              = client['cvedb']['cves']

kwargs  = {
    'java' : { 
        'compile' : 'y',
        'command' : 'javac'
    }
}
list_Of_Compiler_Procedures = defaultdict(dict, **kwargs)

def create_Linux_Patch():
    pass

def format_Code_Deletions():
    pass

def search_URL_For_BFS_Update():
    pass

# search_For_Deletions(remove_code, '../file_store/test/test1.py')

# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
#                           Lexer related functions                        |
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------

# Tokens for parsing code
tokens = (
   'NUMBER',
   'VARIABLE',
   'STRING',
   'OPERATOR',
   'LPAREN',
   'RPAREN',
   'LBRACE',
   'RBRACE',
)

# Regular expression rules 
t_NUMBER    = r'[-+]?[0-9]*\.?[0-9]+'
t_VARIABLE  = r'[a-zA-Z][a-zA-Z0-9_]*'
t_STRING    = r'\"(.+?)\" | \'(.+?)\''
t_OPERATOR  = r'\= | \+ | \- | \/ | \:'
t_LPAREN    = r'\('
t_RPAREN    = r'\)'
t_LBRACE    = r'\{'
t_RBRACE    = r'\}'

# Ignore characters
t_ignore    = ' \t\n'

# Error catching
def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    t.lexer.skip(1)

lexer_for_deletion  = lex.lex()
lexer_for_file      = lex.lex()

def search_For_Deletions(deletions, path_of_file_to_modify):
    
    list_Of_Lexers      = []
    seperate_deletions  = deletions.split("&*&")

    start               = time.time()

    for split_deletions in seperate_deletions:

        lexer_for_deletion.input(split_deletions)
        list_Of_Lexers.append(lexer_for_deletion)

    if (os.path.exists(path_of_file_to_modify)):
        with open(path_of_file_to_modify, 'r') as file_to_search:
            
            data = file_to_search.read().replace('\n', '')
            print(data)
            lexer_for_file.input(data)

            for tok in lexer_for_file:
                for lexers in copy(list_Of_Lexers):
                    
                    start_line      = str(tok.lineno) + ',' + str(tok.lexpos)
                    copy_of_lexer   = copy(lexer_for_file)
                    temp_token      = tok
                    lex_token       = lexers.token()

                    if (temp_token == None or lex_token == None): break

                    print("Tokens to compare:", lex_token.type, temp_token.type)
                    while (lex_token.value == temp_token.value):
                        
                        end_line            = str(temp_token.lineno) + ',' + str(temp_token.lexpos)

                        try:    lex_token   = lexers.token()
                        except: return (start_line, end_line)
                        
                        try:    temp_token  = copy_of_lexer.token()
                        except: break   

                        if (temp_token == None): break
                        if (lex_token == None): return (start_line, end_line)   
                        print("Tokens to compare:", lex_token.type, temp_token.type)
    
    else:   
        print("Path does not exist:", path_of_file_to_modify)
    
    print("Total time for lexer:", time.time() - start)

def remove_Contents_Of_File(path_of_file_to_modify, removal_tuple):
    
    current_var_count       = 1
    range_of_tuple          = range(removal_tuple[0], removal_tuple[1])
    destination             = open("../file_store/test/new_File.py", "w")

    if (os.path.exists(path_of_file_to_modify)):
        with open(path_of_file_to_modify, 'r') as file_to_search:
            for items in file_to_search:

                current_string = ""
                
                for letters in items.replace('\n', ''):
                    
                    if (current_var_count not in range_of_tuple):
                        current_string += letters

                    print(letters, current_var_count)
                    current_var_count += 1

                if (current_string):
                    destination.write(current_string + '\n')

def get_Diff_Of_Files(file_path1, file_path2):
    pass

data = '''
    def hello():
        print("Say hello")
    '''

# print(search_For_Deletions(data, '../file_store/test/test1.py'))
remove_Contents_Of_File('../file_store/test/test1.py', (1, 32))