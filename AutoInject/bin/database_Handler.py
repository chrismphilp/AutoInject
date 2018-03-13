import pymongo

from    json                            import loads
from    bson.json_util                  import dumps
from    pymongo                         import MongoClient

import AutoInject.bin.get_Packages      as gp
import AutoInject.bin.system_Functions  as sf

client                      = MongoClient()
admin_patch_collection      = client['package_db']['admin_patches']
auto_increment_coll         = client['package_db']['auto_increment']
cve_collection              = client['cvedb']['cves']
package_collection          = client['package_db']['package_list']
user_collection             = client['user_db']['users']

class Database:
    def __init__(self):
        self.update_Admin_Patch_Colletion_JSON()
        self.update_Matched_Vulnerability_Packages_JSON()
        self.update_Package_JSON()
        self.update_Update_Log()
        self.update_User_Collection_JSON()

    # ---  --- ---  --- ---  --- ---  --- --- 
    # ---   Package related functions     ---
    # ---  --- ---  --- ---  --- ---  --- ---

    def update_Package_JSON(self):
        self.package_collection_json = dumps(package_collection.find({}))

    def hard_Reset_Packages(self):
        package_collection.remove({})
        cve_collection.update(
            {},
            { '$unset' : { 
                'matched_To_CVE' : 1, 
                'matched_to' : 1
            } }
        )
        package_Data = gp.get_Package_Data()
        self.insert_Packages(package_Data[0])
        remove_Special_Characters()
        search_New_Vulnerabilities(package_Data)
        self.update_Package_JSON()

    def insert_Packages(self, package_List):
        print('Inserting new packages into database')
        package_collection.drop()
        package_collection.insert(package_List)

    # ---  --- ---  --- ---  --- ---  --- --- 
    # --- Vulnerability related functions ---
    # ---  --- ---  --- ---  --- ---  --- ---

    def update_Matched_Vulnerability_Packages_JSON(self):
        self.packages_with_vulnerabilities = dumps(package_collection.find({
            'matching_ids' : { '$exists' : True, '$not' : { '$size' : 0 } },
            'updateable' : 1
        }) )

    def get_Matching_CVES(self, matching_ids):
        return dumps( 
            cve_collection.find( { 
                'id' : { '$in' : matching_ids },
                'deleted' : { '$ne' : 1 } } 
            ) 
        )

    # ---  --- ---  --- ---  --- ---  --- --- 
    # ---   Update related functions      ---
    # ---  --- ---  --- ---  --- ---  --- ---

    def update_Update_Log(self):
        self.update_log = dumps(package_collection.find( { 'log' : { '$elemMatch' : { 'active' : 0 } } } ))
    
    def get_Specific_Update_Log(self, package_name):
        if package_name:    
            cursor = package_collection.find({
                'package_name' : package_name,
                'log' : { 
                    '$exists' : True,
                    '$not' : { '$size' : 0 } 
                }
            })
            data = { 'log' : [] }
            formatted_data = loads(dumps(cursor))
            for items in formatted_data:
                for logs in items['log']:
                    if logs['active'] == 1: data['log'].append(logs)       
            return dumps(data)

    # ---  --- ---  --- ---  --- ---  --- --- 
    # ---   Admin related functions       ---
    # ---  --- ---  --- ---  --- ---  --- ---    

    def update_Admin_Patch_Colletion_JSON(self):
        self.admin_pacth_collection_json = dumps(admin_patch_collection.find({}))

    def get_Incremented_Id(self):
        if (auto_increment_coll.count() > 0): 
            count = auto_increment_coll.find().sort([('id', -1)]).limit(1)
            for item in count:
                auto_increment_coll.update( 
                    { 'id' : item['id'] },
                    { '$set' : { 'id' : item['id'] + 1 } } 
                )
                return item['id']         
        else: 
            auto_increment_coll.insert( { 'id' : 1 } )
            return 1

    # ---  --- ---  --- ---  --- ---  --- --- 
    # ---   User related functions        ---
    # ---  --- ---  --- ---  --- ---  --- --- 

    def update_User_Collection_JSON(self):
        self.user_collection_json = dumps(user_collection.find({}))
