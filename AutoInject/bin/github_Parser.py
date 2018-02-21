import requests, time, re

# Parsing related modules
import lxml.html    as lh 
import lxml.etree   as etree

from subprocess     import check_output, check_call

def parse_Github(url):
    if not urls(endwith("?diff=split")): url += "?diff=split"
    request_time    = time.time()
    page            = requests.get(url)
    print('Total request time:', time.time() - request_time)
    tree            = lh.fromstring(page.content)
    list_of_divs    = []
    l_o_i           = ""

    for divs in tree.xpath(
        "//div[re:test(@id, '^diff-[0-9]+')]", 
        namespaces={"re": "http://exslt.org/regular-expressions"}
    ):
        # Get file name
        for lines in divs.findall(".//a[@class='link-gray-dark']"):
            name_of_file = lines.text_content()
        # Get each seperated table row
        for lines in divs.findall(".//table/tr"):

            if 'blob-code blob-code-inner blob-code-hunk' in str(etree.tostring(lines[1])):
                continue
            if 'blob-code blob-code-expandable' in str(etree.tostring(lines[1])):
                continue
            
            first_line              = lines[1].text_content().replace('\n', '')
            second_line             = lines[3].text_content().replace('\n', '')
            length_of_space_first   = len(first_line) - len(first_line.lstrip())
            length_of_space_second  = len(second_line) - len(second_line.lstrip())

            if 'code-review blob-code blob-code-context' in str(etree.tostring(lines[1])):
                if 'code-review blob-code blob-code-context' in str(etree.tostring(lines[3])):     
                    if special_Match(first_line): continue
                    else: l_o_i += "&*" + first_line + "\n"
            
            if 'code-review blob-code blob-code-deletion' in str(etree.tostring(lines[1])):
                if 'code-review blob-code blob-code-addition' in str(etree.tostring(lines[3])):
                    if first_line[length_of_space_first] == '-': first_line = first_line[length_of_space_first + 1:]
                    if second_line[length_of_space_second] == '+': second_line = second_line[length_of_space_second + 1:]
                    l_o_i += "&--" + first_line + "\n" + " &++" + second_line + "\n"
                if 'blob-code blob-code-empty empty-cell'in str(etree.tostring(lines[3])):
                    if first_line[length_of_space_first] == '-': first_line = first_line[length_of_space_first + 1:]
                    l_o_i += "&--" + first_line + "\n" + " &++" + "\n"

            if 'blob-code blob-code-empty empty-cell'in str(etree.tostring(lines[1])):
                if 'code-review blob-code blob-code-addition' in str(etree.tostring(lines[3])):
                    if special_Match(second_line): continue
                    else: 
                        if second_line[length_of_space_second] == '+': second_line = second_line[length_of_space_second + 1:]
                        l_o_i += second_line + "\n"

        if l_o_i: list_of_divs.append((name_of_file, l_o_i))
        l_o_i = ""

    print("Total time for GitHub parse:", time.time() - request_time)
    return list_of_divs

def special_Match(strg, search=re.compile(r"[^\n\t\r' ']").search):
    return not bool(search(strg))
