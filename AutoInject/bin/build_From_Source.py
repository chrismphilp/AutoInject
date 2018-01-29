import pymongo, re, time, datetime, os

# Parsing related modules
import AutoInject.bin.patch_Handler as ph

import ply.lex                      as lex
from pygments.lexers                import guess_lexer_for_filename
from shutil                         import copyfile

from pymongo                        import MongoClient
from json                           import loads
from bson.json_util                 import dumps

from subprocess                     import check_output, check_call
from copy                           import copy
from collections                    import defaultdict

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

def search_URL_For_BFS_Update():
    pass

def list_files(startpath):
    for root, dirs, files in os.walk(startpath):
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * (level)
        print('{}{}/'.format(indent, os.path.basename(root)))
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            print('{}{}'.format(subindent, f))

def search_Files():
    pass

def language_Checker(filename, text_Of_Language):
    new     = guess_lexer_for_filename(filename, text_Of_Language)
    print(new)

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

def perform_File_Alterations(path_of_file_to_modify, path_of_new_file, additions, deletions, package_name):
    
    list_Of_Deletion_Tuples = search_For_Deletions(path_of_file_to_modify, deletions)
    print(list_Of_Deletion_Tuples)

    for deletion_items in list_Of_Deletion_Tuples:
        remove_Contents_Of_File(path_of_file_to_modify, path_of_new_file, deletion_items)
    
    format_File_Additions(path_of_new_file, additions)

    ph.produce_Diff_Of_Files(
        'path_of_file_to_modify',
        'path_of_new_file',
        package_name,
        'test_patch_file.patch'
    )

def search_For_Deletions(path_of_file_to_modify, deletions):
    
    list_Of_Deletion_Tuples = []
    seperate_deletions      = deletions.split("&*&")

    start                   = time.time()

    for split_deletions in seperate_deletions:
        lexer_for_deletion.input(split_deletions)
        if (os.path.exists(path_of_file_to_modify)):
            with open(path_of_file_to_modify, 'r') as file_to_search:
                returned_deletions = run_Deletion_Searches(file_to_search, lexer_for_deletion)
                if returned_deletions: list_Of_Deletion_Tuples.append(returned_deletions)
        else:   
            print("File at Path does not exist:", path_of_file_to_modify)

    print("Total time for lexer:", time.time() - start)
    return list_Of_Deletion_Tuples

def run_Deletion_Searches(file_to_modify, lexer_for_deletion):
     
    data = file_to_modify.read().replace('\n', '')
    print(data)
    lexer_for_file.input(data)

    for tok in lexer_for_file:

        copy_of_lexer_for_deletion = copy(lexer_for_deletion)
            
        start_line      = tok.lexpos
        copy_of_lexer   = copy(lexer_for_file)
        deletion_token  = tok
        lex_token       = copy_of_lexer_for_deletion.token()

        if (deletion_token == None or lex_token == None): break

        print("Tokens to compare:", lex_token.value, deletion_token.value)
        while (lex_token.value == deletion_token.value):
            
            end_line                = deletion_token.lexpos + len(deletion_token.value)

            try:    lex_token       = copy_of_lexer_for_deletion.token()
            except: return (start_line, end_line)
            
            try:    deletion_token  = copy_of_lexer.token()
            except: break   

            if (lex_token == None): return (start_line, end_line)
            if (deletion_token == None):    break 

            print("Matched Tokens to compare:", (lex_token.value, lex_token.lexpos),  (deletion_token.value, deletion_token.lexpos))

    print("Finished searching \n")

def remove_Contents_Of_File(path_of_file_to_modify, path_of_new_file, removal_tuple):
    
    current_var_count       = 0
    range_of_tuple          = range(removal_tuple[0], removal_tuple[1])
    destination             = open(path_of_new_file, "w")

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
                    print(current_string)
                    destination.write(current_string + '\n')

def format_File_Additions(path_of_file_to_modify, additions):
    
    if ('&--' in additions):
        destination = open(path_of_file_to_modify, "w")
        pass
    elif('&lo' in additions):
        destination = open(path_of_file_to_modify, "w")
        pass
    else:
        destination = open(path_of_file_to_modify, "a")
        destination.write(additions)
        