import 	sys, os, logging, atexit, time
import 	AutoInject.bin.system_Functions  	as sf
import 	AutoInject.bin.get_Vulnerabilities 	as gv
from 	pymongo                        		import MongoClient
from 	flask 								import Flask, render_template, request, session
from 	apscheduler.schedulers.background 	import BackgroundScheduler
from 	apscheduler.triggers.interval 		import IntervalTrigger

client             	= MongoClient()
user_collection  	= client['user_db']['users']

def init_app():
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = ''
    return app
app = init_app()

from AutoInject.bin import views

def call_database_updater():
	if views.user:
		if (user_collection.find_one( { 'id' : views.user.id } )['auto_update'] == '0'):
			sf.run_Database_Updater_Script()
			gv.collect_Checkable_Packages()

if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
	scheduler = BackgroundScheduler(daemon=True)
	scheduler.start() 
	scheduler.add_job(
		func=call_database_updater,
		trigger=IntervalTrigger(hours=24),
		id='refreshing_database',
		name='Database_Refresh',
		replace_existing=True
	)
	atexit.register(lambda: scheduler.shutdown())

if __name__ == "__main__":
    
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    print("\t\t\t**** Use CTRL+C then Enter key to exit ****")
    print("\t\t\t\tFlask logging mode off")
    print("\t\t\t**** Access to UI at 127.0.0.1:5000 ****\n")
    app.run(debug=True)