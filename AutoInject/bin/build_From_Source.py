import pymongo, re, time, datetime, os

# Parsing related modules
import AutoInject.bin.patch_Handler as ph

import ply.lex                      as lex
from pygments                       import highlight
from pygments.lexers                import guess_lexer_for_filename, get_lexer_by_name
from pygments.styles                import get_all_styles, get_style_by_name
from pygments.formatters            import get_formatter_by_name
from shutil                         import copyfile
from pkg_resources                  import resource_filename

from pymongo                        import MongoClient
from json                           import loads
from bson.json_util                 import dumps

from subprocess                     import check_output, check_call
from copy                           import copy
from collections                    import defaultdict

client                              = MongoClient()
package_collection                  = client['package_db']['package_list']
cve_collection                      = client['cvedb']['cves']

kwargs  = {
    'java' : { 
        'compile' : 'y',
        'command' : 'javac'
    }
}
list_Of_Compiler_Procedures = defaultdict(dict, **kwargs)

def search_URL_For_BFS_Update():
    pass

def search_Files(file_name):
    path_to_script = resource_filename("AutoInject", "/bin/sudo_scripts/update_db")
    os.system(path_to_script)
    list_Of_Files_Found_With_Name = check_output(
        ["locate", file_name],
        universal_newlines=True
    )
    print(list_Of_Files_Found_With_Name)

def format_HTML(filepath):
    with open(filepath, 'r') as file_to_read:
        data            = file_to_read.read()
        lexer_object    = guess_lexer_for_filename(filepath, data)
        pyg_formatter   = get_formatter_by_name('html', linenos='table', style='monokai')
        completed       = highlight(data, lexer_object, pyg_formatter)
        return completed

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
    'NEWLINE',
    'ADD_AFTER',
    'ADD_REPLACE_ADDITION',
    'ADD_REPLACE_REMOVE'
)

# Regular expression rules 
t_NUMBER                = r'[-+]?[0-9]*\.?[0-9]+'
t_VARIABLE              = r'[a-zA-Z][a-zA-Z0-9_]*'
t_STRING                = r'\"(.+?)\" | \'(.+?)\''
t_OPERATOR              = r'\= | \+ | \- | \/ | \:'
t_LPAREN                = r'\('
t_RPAREN                = r'\)'
t_LBRACE                = r'\{'
t_RBRACE                = r'\}'
t_ADD_AFTER             = r'\&\*'
t_ADD_REPLACE_ADDITION  = r'\&\+\+'
t_ADD_REPLACE_REMOVE    = r'\&--'
t_NEWLINE               = r'\n'

# Ignore characters
t_ignore                = ' \t\r'

# Error catching
def t_error(t):
    print("Illegal character '%s'" % t.value)
    t.lexer.skip(1)

lexer_for_addition  = lex.lex()
lexer_for_deletion  = lex.lex()
lexer_for_file      = lex.lex()

def perform_File_Alterations(path_of_file_to_modify, path_of_new_file, additions, deletions, package_name, comment):
    
    perform_Additions(path_of_file_to_modify, path_of_new_file, additions)
    perform_Deletions(path_of_new_file, deletions)

    new_string = ""
    for lines in open(path_of_new_file, 'r'):
        new_string += lines.replace("    ", "\t")
    with open(path_of_new_file, 'w') as destination:
        destination.write(new_string)

    diff_file_path = ph.produce_Diff_Of_Files(
        path_of_file_to_modify,
        path_of_new_file,
        package_name,
        'AutoInject/file_store/test/patch_file.patch',
        comment
    )
    return diff_file_path

# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
#                           Deletion related functions                     |
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------

def perform_Deletions(path_of_file_to_modify, deletions):
    
    list_Of_Deletion_Tuples = []
    seperate_deletions      = deletions.split("&*&")
    start                   = time.time()
    print(seperate_deletions)

    for split_deletions in seperate_deletions:
        
        if split_deletions.startswith("\n"):    split_deletions = split_deletions[1:]
        if split_deletions.endswith("\n"):      split_deletions = split_deletions[:-1]
        
        print(split_deletions)

        lexer_for_deletion.input(split_deletions)
        if (os.path.exists(path_of_file_to_modify)):
            with open(path_of_file_to_modify, 'r') as file_to_search:
                returned_deletions = run_Deletion_Searches(file_to_search, lexer_for_deletion)
                if returned_deletions: list_Of_Deletion_Tuples.append(returned_deletions)
        else:   
            print("File at Path does not exist:", path_of_file_to_modify)

    print("Total time for lexer:", time.time() - start)
    print(list_Of_Deletion_Tuples)
    remove_Contents_Of_File(path_of_file_to_modify, path_of_file_to_modify, list_Of_Deletion_Tuples)

def run_Deletion_Searches(file_to_modify, lexer_for_deletion):
     
    data = file_to_modify.read()
    lexer_for_file.input(data)

    for tok in lexer_for_file:

        copy_of_lexer_for_deletion  = copy(lexer_for_deletion)
        start_line                  = tok.lexpos
        copy_of_lexer               = copy(lexer_for_file)
        deletion_token              = copy_of_lexer_for_deletion.token()
        lex_token                   = tok

        if (deletion_token == None or lex_token == None): break

        print("Tokens to compare:", lex_token.value, deletion_token.value)
        while (lex_token.value == deletion_token.value):
            
            end_line                = lex_token.lexpos + len(lex_token.value)

            try:    deletion_token  = copy_of_lexer_for_deletion.token()
            except: return (start_line, end_line)
            
            try:    lex_token  = copy_of_lexer.token()
            except: break   

            if (deletion_token == None):    return (start_line, end_line)
            if (lex_token == None):         break 

            print("Matched Tokens to compare:", (lex_token.value, lex_token.lexpos),  (deletion_token.value, deletion_token.lexpos))

    print("Finished searching \n")

def remove_Contents_Of_File(path_of_file_to_modify, path_of_new_file, removal_tuples):
    
    current_var_count   = 0
    current_string      = ""

    if (os.path.exists(path_of_file_to_modify)):
        with open(path_of_file_to_modify, 'r') as file_to_search:
            for characters in file_to_search.read():
                match = False
                for single_tuple in removal_tuples:
                    if current_var_count in range(single_tuple[0], single_tuple[1]): match = True
                if not match: current_string += characters
                current_var_count += 1

    with open(path_of_file_to_modify, 'r') as file_to_search:
        var = 0
        for characters in file_to_search.read():
            print(characters, var)
            var += 1

    if current_string:
        with open(path_of_new_file, "w") as destination:
            print(current_string)
            destination.write(current_string)

# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
#                           Addition related functions                     |
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------

def perform_Additions(path_of_file_to_modify, path_of_file_to_write, additions):
    
    split_Additions             = additions.split("&*&")
    list_Of_Insertion_Tuples    = []

    for addition_Strings in split_Additions:
        
        addition_Strings = "\n" + addition_Strings 
        addition_Strings += "\n"
        
        print(addition_Strings)

        lexer_for_addition.input(addition_Strings)  
        tuple_Array = get_Tuples_For_Addition(path_of_file_to_modify, lexer_for_addition, addition_Strings)

        if tuple_Array: list_Of_Insertion_Tuples.extend(tuple_Array)
        else: continue 

    if      list_Of_Insertion_Tuples: run_Addition_Searches(path_of_file_to_modify, path_of_file_to_write, list_Of_Insertion_Tuples)  
    else:   print("No additions to add"); return False

def get_Tuples_For_Addition(path_of_file_to_modify, lexer_for_addition, addition_string):

    list_Of_Insertion_Tuples    = []

    with open(path_of_file_to_modify, 'r') as file_to_modify:
            
        data = file_to_modify.read()
        lexer_for_file.input(data)
        token = lexer_for_file.token()

        addition_token  = lexer_for_addition.token()
        loop            = True
        start_pos       = token.lexpos
        end_pos         = token.lexpos
        point_to_insert = 0

        while loop:

            copy_of_lexer_for_file      = copy(lexer_for_file)
            copy_of_token_for_file      = token

            if (addition_token == None or copy_of_token_for_file == None): break

            start_line                  = token.lexpos
            matched = False

            if (addition_token.type == 'ADD_AFTER'):

                print("Found add after token", addition_token)

                try:    addition_token  = lexer_for_addition.token()
                except: return False
                
                copy_of_lexer_for_addition  = copy(lexer_for_addition) 
                copy_of_addition_token      = addition_token

                while (copy_of_token_for_file != None and matched == False):

                    # Matching the start of the addition lexer start to the lexer for the file token
                    while (token != None and copy_of_addition_token != None 
                        and token.value != copy_of_addition_token.value): 

                        try:    token = lexer_for_file.token()
                        except: return False

                    copy_of_lexer_for_addition  = copy(lexer_for_addition)
                    copy_of_addition_token      = addition_token

                    copy_of_lexer_for_file      = copy(lexer_for_file)
                    copy_of_token_for_file      = token

                    while (copy_of_token_for_file != None and copy_of_addition_token != None 
                        and copy_of_addition_token.value == copy_of_token_for_file.value and matched == False):
                        
                        if (copy_of_addition_token.type == 'NEWLINE'):

                            start_pos = copy_of_addition_token.lexpos + 1

                            try:    copy_of_addition_token = copy_of_lexer_for_addition.token()
                            except: return list_Of_Insertion_Tuples

                            while (addition_token.lexpos != copy_of_addition_token.lexpos):
                                addition_token = lexer_for_addition.token()
                                print("Copy of addition token lex pos is:", copy_of_addition_token.value, copy_of_addition_token.lexpos)
                                print("Addition token lex pos is:", addition_token.value, addition_token.lexpos)
                            
                            # Getting the token for the file in line with the copy that has matched
                            while (token.lexpos != copy_of_token_for_file.lexpos):
                                token = lexer_for_file.token()
                                print("Token value:", token, "Token copy value:", copy_of_token_for_file)

                            matched = True
                            break

                        elif (matched == False):
                            try:    copy_of_addition_token = copy_of_lexer_for_addition.token()
                            except: 
                                print("GOT A MATCH")
                                # Matching the addition lexer to its copy which has matches
                                while (addition_token.lexpos != copy_of_addition_token.lexpos): addition_token = lexer_for_addition.token()

                                # Getting the token for the file in line with the copy that has matched
                                while (token.lexpos != copy_of_token_for_file.lexpos):
                                    print("Token lexpos:", token.lexpos, "Token copy value:", copy_of_token_for_file.value)
                                    token = lexer_for_file.token()
                                matched = True

                            try:    copy_of_token_for_file = copy_of_lexer_for_file.token()
                            except: print(copy_of_token_for_file)

                print("Done with finding area to append at")
                point_to_insert = token.lexpos + 1

            elif (addition_token.type == 'ADD_REPLACE_REMOVE'):
                print("Found add replace remove")

                matched = False

                try:    addition_token  = lexer_for_addition.token()
                except: return False

                while (matched == False):    

                    copy_of_lexer_for_addition  = copy(lexer_for_addition)
                    copy_of_addition_token      = addition_token

                    while (token != None and copy_of_addition_token != None 
                        and token.value != copy_of_addition_token.value):      
                        
                        try:    token = lexer_for_file.token()
                        except: return False
                    
                    start_position_to_remove = token.lexpos

                    copy_of_lexer_for_file      = copy(lexer_for_file)
                    copy_of_token_for_file      = token

                    while (copy_of_token_for_file != None and copy_of_addition_token != None 
                        and copy_of_token_for_file.value == copy_of_addition_token.value and matched == False):
                        
                        if (copy_of_addition_token.type == 'NEWLINE'):
                            
                            while (addition_token.lexpos != copy_of_addition_token.lexpos):
                                addition_token = lexer_for_addition.token()
                            
                            while (token != None and copy_of_addition_token != None 
                                and token.value != copy_of_addition_token.value):      
                                
                                try:    token = lexer_for_file.token()
                                except: return False
                            
                            end_position_to_remove = token.lexpos
                            matched = True
                        else:
                            try:    copy_of_addition_token = copy_of_lexer_for_addition.token()
                            except: 
                                while (addition_token.lexpos != copy_of_addition_token.lexpos):
                                    addition_token = lexer_for_addition.token()
                                matched = True

                            try:    copy_of_token_for_file = copy_of_lexer_for_file.token()
                            except: return False

                    if (copy_of_addition_token.type == 'NEWLINE'): 
                        
                        try:    copy_of_addition_token = copy_of_lexer_for_addition.token()
                        except: return False

                        while (addition_token.lexpos != copy_of_addition_token.lexpos):
                            try:    addition_token = lexer_for_addition.token()
                            except: return False
    
                    if (copy_of_addition_token.type == 'ADD_REPLACE_ADDITION'):    
                        
                        try:    copy_of_addition_token = copy_of_lexer_for_addition.token()
                        except: return False
                    
                        start_pos       = copy_of_addition_token.lexpos

                        while (copy_of_addition_token.type != 'NEWLINE'):
                            try:    copy_of_addition_token = copy_of_lexer_for_addition.token()
                            except: return list_Of_Insertion_Tuples
                        
                        string_to_add   = ""
                        end_pos         = copy_of_addition_token.lexpos + len(copy_of_addition_token.value) - 1
                        count           = 0

                        for characters in addition_string:
                            if (start_pos <= count <= end_pos):
                                string_to_add   += characters
                                count           += 1
                            else: count += 1
                        
                        list_Of_Insertion_Tuples.append((start_position_to_remove, end_position_to_remove, string_to_add))
                        print(list_Of_Insertion_Tuples)

                        while (addition_token.lexpos != copy_of_addition_token.lexpos):
                            try:    addition_token = lexer_for_addition.token()
                            except: return False

                        matched = True

                if token: point_to_insert = token.lexpos

                start_pos = addition_token.lexpos
            
            elif (addition_token.type == 'NEWLINE'):
                print("Found newline")

                if addition_token: print(addition_token); start_pos = addition_token.lexpos

                try:    addition_token = lexer_for_addition.token()
                except: print("No token after Newline"); return list_Of_Insertion_Tuples
            
            # Standard addition
            else: 
                while (addition_token != None and addition_token.type != 'NEWLINE'):
                    try:    addition_token = lexer_for_addition.token()
                    except: end_pos = addition_token.lexpos

                string_to_add   = ""
                if addition_token: print("End pos:", addition_token); end_pos = addition_token.lexpos
                count           = 0

                for characters in addition_string:
                    if (start_pos + 1 <= count <= end_pos):
                        string_to_add   += characters
                        count           += 1
                    else: count += 1

                if addition_token: start_pos = addition_token.lexpos

                list_Of_Insertion_Tuples.append((point_to_insert, string_to_add)) 

    print("Retuning:", list_Of_Insertion_Tuples)
    return list_Of_Insertion_Tuples

def run_Addition_Searches(path_of_file_to_modify, path_of_file_to_write, list_Of_Insertion_Tuples):
    
    string_for_file = ""
    count_of_characters = 0
    print("List to use:", list_Of_Insertion_Tuples)

    if (os.path.exists(path_of_file_to_modify)):   
        with open(path_of_file_to_modify, 'r') as file_to_modify:
            for characters in file_to_modify.read():  
                added = False 
                for tuples in list_Of_Insertion_Tuples:
                    if (type(tuples[1]) is int):
                        if (tuples[1] == count_of_characters): print("Adding at:", count_of_characters); string_for_file += tuples[2]
                        elif (tuples[0] <= count_of_characters <= tuples[1]): added = True
                    elif (tuples[0] == count_of_characters): string_for_file += tuples[1]
                    
                if not added: string_for_file += characters; added = True
                count_of_characters += 1
    
    else: print("Path does not exist to file")

    with open(path_of_file_to_write, 'w') as file_to_write:
        file_to_write.write(string_for_file)

example_Patch = '''
hello
&* class adder:
&-- def hello():
&++ def goodbye():
&-- print("Say hello")
&++ print("Say goodbye")
        print("hola")
    &-- def goodbye(au_dieu):
    &++ def goodbye(au_revoir):
        hello
        y = au_revoir + 1
        return y
&*&
goodbye
'''

test_deletion = '''
def hello():
return "Hello"
&*&
y = au_revoir + 1
return y
'''

perform_Deletions('../file_store/test/test1.py', test_deletion)