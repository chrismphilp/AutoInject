import pymongo

from pymongo            import MongoClient
try:                    import httplib
except:                 import http.client as httplib

# Database API
client                      = MongoClient()
auto_increment_coll         = client['package_db']['auto_increment']

def connected_To_Internet():
    conn = httplib.HTTPConnection("www.google.com", timeout=5)
    try:
        conn.request("/HEAD", "/")
        conn.close()
        return True
    except:
        conn.close()
        return False

def get_Incremented_Id():
    if (auto_increment_coll.count() == 0): 
        auto_increment_coll.insert( { 'id' : 1 } )
        return 1 
    else: 
        count = auto_increment_coll.find().sort([('id', -1)]).limit(1)
        for item in count:
            auto_increment_coll.update( 
                { 'id' : item['id'] },
                { '$set' : { 'id' : item['id'] + 1 } },
                False,
                True 
            )
            return item['id']
