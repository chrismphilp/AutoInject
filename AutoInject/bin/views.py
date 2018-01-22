import pymongo, json, datetime

from json               import loads
from bson.json_util     import dumps
from flask              import Flask, render_template, request, redirect, url_for
from pymongo            import MongoClient

from AutoInject         import app

# Importing scripts to sort data
import AutoInject.bin.get_Vulnerabilities   as gv
import AutoInject.bin.get_Packages          as gp
import AutoInject.bin.system_functions      as sf

# Flask-login
from flask_login        import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from wtforms            import Form, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_wtf          import FlaskForm
from werkzeug.security  import check_password_hash, generate_password_hash

login_manager            = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database API
client                  = MongoClient()
package_collection      = client['package_db']['package_list']
cve_collection          = client['cvedb']['cves']
user_collection         = client['user_db']['users']

@app.route("/")
@login_required
def index():  
    package_JSON_data = gp.get_Packages_JSON()
    return render_template('index.html', package_JSON_data=package_JSON_data)

@app.route("/drop")
@login_required
def drop():  
    print("Dropping and refreshing packages")
    cve_collection.update( 
        {}, 
        { '$unset' : { 'matched_To_CVE' : 1 } }, 
        multi=True 
    )
    package_JSON_data = gp.get_Package_Data()
    gp.insert_Packages(package_JSON_data)
    gv.remove_Special_Characters()
    gv.collect_Checkable_Packages()
    return redirect("/", code=302)

@app.route("/refresh")
@login_required
def refresh():  
    print("Refreshing vulnerabilities")
    gv.run_Database_Updater_Script()
    gv.remove_Special_Characters()
    gv.collect_Checkable_Packages()
    return redirect("/", code=302)

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

@app.route("/vulnerabilities")
@login_required
def vulnerabilities():

    vulnerability_JSON_data = gv.return_Matched_Vulnerability_Values()
    return render_template('vulnerabilities.html', vulnerability_JSON_data=vulnerability_JSON_data)

@app.route("/vulnerabilities/<package>")
@login_required
def return_CVE_IDs(package):

    cursor = package_collection.find( { 'formatted_package_name_with_version' : package } )

    list_Of_Values = []
    for values in cursor:
        list_Of_Values.extend(values['matching_ids'])

    vulnerabilities = loads(dumps( cve_collection.find( { 'id' : { '$in' : list_Of_Values } } ) ))
    return render_template('individual_package.html', vulnerabilities=vulnerabilities, package=package)

@app.route("/version_update", methods=['POST'])
@login_required
def version_update():
    version_name    = request.form['version-name']
    link            = request.form['link']
    comment         = request.form['comment']
    package         = request.form['package']
    print(version_name, link, comment, package)
    return redirect("/vulnerabilities/" + package, code=302)

@app.route("/manual_update", methods=['POST'])
@login_required
def manual_update():
    filepath    = request.form['file-path']
    insert_code = request.form['inserted-code']
    remove_code = request.form['removed-code']
    comment     = request.form['comment']
    package     = request.form['package']
    print(filepath, insert_code, remove_code, comment, package)
    return redirect("/vulnerabilities/" + package, code=302)

@app.route("/log")
@login_required
def log():
    return render_template('log.html')

@app.route("/profile")
@login_required
def profile():
    return render_template('profile.html')

@app.route("/about")
def about():
    return render_template('about.html')

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

            if check_password_hash(result['password'], request.form['password']):
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

    if request.method == 'GET':
        print("Received GET request for register form")
        return render_template('login.html', form=form)
    elif request.method == 'POST':
        if form.validate_on_submit():
            print("Registering User")
            if (user_collection.find( { 'email' : request.form['email'] } ).count() 
                or
                user_collection.find( { 'id' : request.form['username'] } ).count()):
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
