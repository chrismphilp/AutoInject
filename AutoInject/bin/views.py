import pymongo, json, datetime

from json import loads
from bson.json_util import dumps
from flask import Flask, render_template, request, redirect
from pymongo import MongoClient

from AutoInject import app

# Importing scripts to sort data
import AutoInject.bin.get_Vulnerabilities as gv
import AutoInject.bin.get_Packages as gp
import AutoInject.bin.system_functions as sf

# Flask-login
from flask_login        import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from wtforms            import Form, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_wtf          import FlaskForm

login_manager            = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database API
client                  = MongoClient()
package_collection      = client['package_db']['package_list']
cve_collection          = client['cvedb']['cves']

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
#                           Login related functions
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------

app.secret_key = 'philpy'

class User(UserMixin):
    pass

class SignupForm(FlaskForm):
    email       = StringField('email', validators=[DataRequired(), Email()])
    password    = PasswordField('password', validators=[DataRequired()])
    submit      = SubmitField("Sign In")

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route("/login", methods=['POST', 'GET'])
def login():

    form = UserLoginForm()
    
    if form.validate_on_submit():
        login_user(user)
        flask.flash('Logged in Successfully')

    return render_template('login.html', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return True

@app.route("/register", methods=['POST', 'GET'])
def register():
    
    form = SignupForm()

    if request.method == 'GET':
        return render_template('register.html', form=form)
    elif request.method == 'POST':
        if form.validate_on_submit():
            if 'user_exists':
                return True
            else:
                return False
        else:
            return False