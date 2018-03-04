import pymongo, json

from datetime           import datetime
from json               import loads
from bson.json_util     import dumps
from flask              import Flask, render_template, request, redirect, url_for
from pymongo            import MongoClient

from AutoInject         import app

# Importing scripts to sort data
import AutoInject.bin.apply_Patches         as ap
import AutoInject.bin.build_From_Source     as bfs
import AutoInject.bin.get_Packages          as gp
import AutoInject.bin.get_Vulnerabilities   as gv
import AutoInject.bin.patch_Handler         as ph
import AutoInject.bin.system_Functions      as sf

# Flask-login
from flask_login        import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from wtforms            import Form, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_wtf          import FlaskForm
from werkzeug.security  import check_password_hash, generate_password_hash

login_manager               = LoginManager()
login_manager.init_app(app)
login_manager.login_view    = 'login'

# Database API
client                      = MongoClient()
package_collection          = client['package_db']['package_list']
admin_patches               = client['package_db']['admin_patches']
cve_collection              = client['cvedb']['cves']
user_collection             = client['user_db']['users']

@app.route("/")
@login_required
def index():  
    package_JSON_data = gp.get_Packages_JSON()
    return render_template('index.html', package_JSON_data=package_JSON_data)

@app.route("/vulnerabilities")
@login_required
def vulnerabilities():
    vulnerability_JSON_data = gv.return_Matched_Vulnerability_Values()
    return render_template('vulnerabilities.html', vulnerability_JSON_data=vulnerability_JSON_data)

@app.route("/vulnerabilities/<package>")
@login_required
def return_CVE_IDs(package):
    list_Of_Values = []
    for values in package_collection.find( { 'formatted_package_name_with_version' : package } ):
        list_Of_Values.extend(values['matching_ids'])

    vulnerabilities = loads(dumps( 
        cve_collection.find( { 
            'id' : { '$in' : list_Of_Values },
            'deleted' : { '$ne' : 1 } } 
        ) 
    ))
    update_log = ap.get_Update_Log(package)

    return render_template(
        'individual_package.html', 
        vulnerabilities=vulnerabilities, 
        package=package,
        update_log=update_log
    )

@app.route("/log")
@login_required
def log():
    package_JSON_data = ap.get_Update_Log()
    return render_template('log.html', package_JSON_data=package_JSON_data)

@app.route("/profile")
@login_required
def profile():
    return render_template('profile.html')

@app.route("/about")
def about():
    return render_template('about.html')

# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
#                           Update Related Functions                       |
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------

@app.route("/version_update", methods=['POST'])
@login_required
def version_update():
    prev_package = package_collection.find_one( 
        { 'formatted_package_name_with_version' : request.form['package'] } 
    )

    if not ap.handle_Version_Patch_By_User(
        request.form['package'],
        request.form['version-name'],
        request.form['link'],
        request.form['comment']
    ): return redirect(url_for('vulnerabilities') + '/' + request.form['package'])
    gv.remove_Special_Characters()
    gv.collect_Checkable_Packages()

    new_package_name = package_collection.find_one( 
        { 'package_name' : prev_package['package_name'] } 
    )

    return render_template(
        'package_alterations.html',
        previous_version=prev_package['current_ubuntu_version'],
        new_version=new_package_name['current_ubuntu_version'],
        link_For_Button="/vulnerabilities/"+new_package_name['formatted_package_name_with_version']
    )

@app.route("/manual_update", methods=['POST'])
@login_required
def manual_update():
    full_file_path = bfs.search_Files(request.form['file-path'])
    html_To_Parse_Before = bfs.format_HTML(full_file_path)

    diff_file_path = ap.handle_Manual_Patch_By_User(
        full_file_path,
        request.form['package'],
        request.form['inserted-code'],
        request.form['comment']
    )

    if not diff_file_path: return redirect(url_for('vulnerabilities') + '/' + request.form['package'])

    html_To_Parse_After = bfs.format_HTML('AutoInject/file_store/test/patch_file.py')
    html_For_Diff_File  = bfs.format_HTML(diff_file_path)

    return render_template(
        'file_alterations.html', 
        html_To_Parse_Before=html_To_Parse_Before,
        html_To_Parse_After=html_To_Parse_After,
        html_For_Diff_File=html_For_Diff_File,
        link_For_Button="/vulnerabilities/"+request.form['package']
    )

@app.route("/vulnerabilities/<package>/package_update/<admin_id>")
@login_required
def update_using_admin_patch(package, admin_id):
    ap.handle_Patch_Update(cve_collection.find_one( { 'id' : admin_id } ) )
    return redirect(url_for('vulnerabilities') + '/' + package)

@app.route("/vulnerabilities/<package>/delete_patch/<date_of_patch>")
@login_required
def delete_file_patch(package, date_of_patch):
    ph.delete_Patch(package, date_of_patch)
    return redirect(url_for('log'))

@app.route("/vulnerabilities/<package>/revert_patch/<date_of_patch>")
@login_required
def reverse_file_patch_package_page(package, date_of_patch):
    ph.handle_Patch_Maintenance(package, date_of_patch)
    gv.remove_Special_Characters()
    gv.collect_Checkable_Packages()
    return redirect(url_for('vulnerabilities') + '/' + package)

@app.route("/log/<package>/revert_patch/<date_of_patch>")
@login_required
def reverse_file_patch_log_page(package, date_of_patch):
    ph.handle_Patch_Maintenance(package, date_of_patch)
    gv.remove_Special_Characters()
    gv.collect_Checkable_Packages()
    return redirect(url_for('log'))
    
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
#                           Login related functions                        |
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------

app.secret_key = 'philpy'

class User(UserMixin):   
    @staticmethod
    def validate_login(hashed_password, password):
        return check_password_hash(hashed_password, password)

class SignupForm(FlaskForm):
    username    = StringField('username', validators=[DataRequired()]) 
    email       = StringField('email', validators=[DataRequired(), Email()])
    password    = PasswordField('password', validators=[DataRequired()])
    submit      = SubmitField("Register")

class LoginForm(FlaskForm):
    email       = StringField('email')      
    username    = StringField('username', validators=[DataRequired()]) 
    password    = PasswordField('password', validators=[DataRequired()])
    submit      = SubmitField("Sign In")

@login_manager.user_loader
def load_user(user_id):
    data                = user_collection.find_one( { 'id' : user_id } )
    user                = User()
    user.id             = data['id']
    user.email          = data['email']
    user.notifications  = data['notifications']
    user.auto_update    = data['auto_update']
    return user

@app.route("/login", methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            result = user_collection.find_one( { 'id' : request.form['username'] } )
            if not result: return redirect(url_for("login"))
            elif check_password_hash(result['password'], request.form['password']):
                user    = User()
                user.id = result['id']
                login_user(user)
                return redirect(url_for("vulnerabilities"))
            else:
                print("Passwords do not match")
                return render_template('login.html', form=form)

    return render_template('login.html', form=form)

@app.route("/register", methods=['POST', 'GET'])
def register():
    form = SignupForm()
    if request.method == 'GET': return render_template('login.html', form=form)
    elif request.method == 'POST':
        if form.validate_on_submit():
            print("Registering User")
            if user_collection.find().count():
                print("User already registered")
                return render_template('login.html', form=form)
            else:
                user_collection.insert({
                    'id' : request.form['username'],
                    'email' : request.form['email'],
                    'password' : generate_password_hash(request.form['password']),
                    'auto_update' : 1,
                    'notifications' : 1
                })
                return render_template('login.html', form=form)
        else:
            print("Form could not be validated")
            return redirect(url_for('login'))

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/forgot_password", methods=['POST', 'GET'])
def forgot_password():
    return render_template('forgot_password.html')

@app.route("/delete_account", methods=['POST', 'GET'])
def delete_account():
    account = user_collection.remove( { 'id' : request.form['username'] } )
    logout_user()
    return redirect(url_for('login'))

@app.route("/change_password", methods=['POST', 'GET'])
def change_password():
    account = user_collection.update(
        { 'id' : request.form['username'] },
        { '$set' : { 'password' : generate_password_hash(request.form['password']) } },
        multi=True
    )
    return redirect(url_for('profile'))  

@app.route("/update_notifications", methods=['POST', 'GET'])
def update_notifications():
    account = user_collection.update( 
        { 'id' : request.form['username'] }, 
        { '$set' : { 'notifications' : request.form['notification'] } },
        multi=True
    )
    return redirect(url_for('profile'))

@app.route("/update_auto_update", methods=['POST', 'GET'])
def update_auto_update():
    account = user_collection.update( 
        { 'id' : request.form['username'] }, 
        { '$set' : { 'auto_update' : request.form['auto_update'] } },
        multi=True
    )
    return redirect(url_for('profile'))

# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
#                           Admin related functions                        |
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------

@app.route("/admin_settings")
@login_required
def admin_settings():
    patch_JSON_data   = loads(dumps(admin_patches.find()))
    user_JSON_data    = loads(dumps(user_collection.find()))
    return render_template("admin_settings.html", user_JSON_data=user_JSON_data, patch_JSON_data=patch_JSON_data)

@app.route("/admin_settings/delete_user/<email>")
@login_required
def admin_delete_user(email):
    user_collection.remove( { 'email' : email } )
    return redirect(url_for('admin_settings'))

@app.route("/admin_registration", methods=['POST'])
@login_required
def admin_registration():
    if (user_collection.find( { 'email' : request.form['email'] } ).count() 
            or
        user_collection.find( { 'id' : request.form['username'] } ).count()):
        print("User already registered")
    else:
        user_collection.insert({
            'id' : request.form['username'],
            'email' : request.form['email'],
            'password' : generate_password_hash(request.form['password']),
            'auto_update' : 1,
            'notifications' : 1
        })
    return redirect(url_for('admin_settings'))

@app.route("/admin_add_manual_update", methods=['POST'])
@login_required
def admin_add_manual_update():      
    admin_patches.insert({
        'id' :'ADMIN-' + str(sf.get_Incremented_Id()),
        'package_name' : request.form['package'] + ''.join(e for e in request.form['package_version'] if e.isalnum()),
        'individual_package_name' : request.form['package'],
        'patch_type' : 'build_from_source',
        'file_path' : request.form['file-path'],
        'update_code' : request.form['inserted-code'],
        'link' : request.form['link'],
        'cvss' : request.form['cvss'],
        'comment' : request.form['comment'],
        'date' : str(datetime.now())
    })
    return redirect(url_for('admin_settings'))

@app.route("/admin_add_version_update", methods=['POST'])
@login_required
def admin_add_version_update():      
    admin_patches.insert({
        'id' :'ADMIN-' + str(sf.get_Incremented_Id()),
        'package_name' : request.form['package'] + ''.join(e for e in request.form['package_version'] if e.isalnum()), 
        'individual_package_name' : request.form['package'],
        'patch_type' : 'version',
        'link' : request.form['link'],
        'version_number' : request.form['version-name'],
        'cvss' : request.form['cvss'],
        'comment' : request.form['comment'],
        'date' : str(datetime.now())
    })
    return redirect(url_for('admin_settings'))

@app.route("/admin_settings/release_patch/<date>")
@login_required
def admin_release_patch(date):
    
    patch_data                  = admin_patches.find_one( { 'date' : date } )
    vulnerable_configuration    = [ patch_data['package_name'] ]
    
    if      patch_data['link']: references = [ patch_data['link'] ]
    else:   references = []

    if (patch_data['patch_type'] == 'build_from_source'):
        cve_collection.insert({
            'id' : patch_data['id'],
            'vulnerable_configuration' : vulnerable_configuration,
            'individual_package_name' : patch_data['individual_package_name'],
            'summary' : patch_data['comment'],
            'cvss' : patch_data['cvss'],
            'patch_type' : 'build_from_source',
            'file_path' : patch_data['file_path'],
            'update_code' : patch_data['update_code'],
            'references' : references,
            'reformatted_configs' : vulnerable_configuration,
            'date' : patch_data['date']
        })
    elif (patch_data['patch_type'] == 'version'):
        cve_collection.insert({
            'id' : patch_data['id'],
            'vulnerable_configuration' : vulnerable_configuration,
            'individual_package_name' : patch_data['individual_package_name'],
            'summary' : patch_data['comment'],
            'cvss' : patch_data['cvss'],
            'patch_type' : 'version',
            'version_number' : patch_data['version_number'],
            'references' : references,
            'reformatted_configs' : vulnerable_configuration,
            'date' : patch_data['date']
        })
    admin_patches.remove( { 'date' : date } )
    return redirect(url_for('admin_settings'))

@app.route("/admin_settings/delete_patch/<date>")
@login_required
def admin_delete_patch(date):
    print("Deleting item", date)
    admin_patches.remove( { 'date' : date } )
    return redirect(url_for('admin_settings'))

# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
#                           Navbar related functions                       |
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------

@app.route("/hard_reset")
@login_required
def hard_reset(): 
    print("Dropping and refreshing packages")
    gv.hard_Reset_Packages()
    return redirect("/", code=302)

@app.route("/refresh")
@login_required
def refresh():  
    print("Refreshing vulnerabilities")
    gv.remove_Special_Characters()
    gv.collect_Checkable_Packages()
    return redirect(url_for('vulnerabilities'), code=302)

@app.route("/update_vulnerabilities")
@login_required
def update_vulnerabilities():  
    gv.run_Database_Updater_Script()
    return redirect(url_for('vulnerabilities'), code=302)

@app.route("/enable/<package>")
@login_required
def enabler(package):
    package_collection.update(
        { 'package_name' : package },
        { '$set' : { 'updateable' : 1 } },
        multi=True
    )
    return redirect("/", code=302)

@app.route("/disable/<package>")
@login_required
def disabler(package):
    package_collection.update(
        { 'package_name' : package },
        { '$set' : { 'updateable' : 0 } },
        multi=True
    )
    return redirect("/", code=302)

@app.route("/vulnerabilities/<package>/disable_cve/<cve_id>")
@login_required
def disable_cve(package, cve_id):
    cve_collection.update(
        { 'id' : cve_id },
        { '$set' : { 'deleted' : 1 } }
    )
    return redirect(url_for('vulnerabilities') + '/' + package, code=302)

@app.route("/enable_all")
@login_required
def enable_all():
    package_collection.update(
        {},
        { '$set' : { 'updateable' : 1 } },
        multi=True
    )
    return redirect("/", code=302)

@app.route("/disable_all")
@login_required
def disable_all():
    package_collection.update(
        {},
        { '$set' : { 'updateable' : 0 } },
        multi=True
    )
    return redirect("/", code=302)