from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import MySQLConnector
import flask
import md5 # imports the md5 module to generate a hash
import os, binascii # for generating random salt
import re 

app = Flask(__name__)
mysql = MySQLConnector(app,'friendsdb')
app.secret_key = "ThisIsSecret!"

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'^[a-zA-Z]+[a-zA-Z-]*[a-zA-Z]+$')

@app.route('/', methods=['GET'])
def index():
  return render_template("index.html")

@app.route('/welcome', methods=['GET'])
def welcomePage():
  return render_template("welcome.html")

@app.route('/register', methods=['POST','GET'])
def submit():
    isform_valid= True
    isGoodForm =1

    if (flask.request.method == 'POST'):
        #Check email field is not blank 
        if len(request.form['email']) < 1:
            flash("Email cannot be blank!")
            isform_valid = False
        # else if email doesn't match regular expression display an "invalid email address" message
        if not EMAIL_REGEX.match(request.form['email']):
            flash("Invalid Email Address!")
            isform_valid = False

        #LOGIC TO CHECK IF EMAIL EXISTS IN DB ----ONLY unique values in DB no repetation 
        email = request.form['email']
        password = request.form['password']
        user_query = "SELECT * FROM user WHERE email = :email LIMIT 1"
        query_data = {'email': email}
        user = mysql.query_db(user_query, query_data)
        if len(user) >= 1:
            flash("Email exists")
            isform_valid = False
            print "Email exists"
            isGoodForm = 0
        # enteredEmail = request.form['email']
        # print "enteredEmail: ", enteredEmail
        # queryToGetEmails = "Select email from user   "
        # existingEmail = mysql.query_db(queryToGetEmails)
        # # for email in existingEmail:
        # #     print "existingEmail: ", email
        # noOfEmails = len(existingEmail) 
        # print "len(existingEmail): ", noOfEmails
        # for i in existingEmail:
        #     # print "i['email']", i['email']

        #     if (i['email'] == enteredEmail):
        #         flash("Email exists")
        #         isform_valid = False
        #         print "Email exists"
        #         isGoodForm = 0
        #

        

        # check if name has 3 or more char
        if len(request.form['fname']) < 3:
            flash(" Name should have more than two characters")
            isform_valid = False
        # check if name matches regex
        if not NAME_REGEX.match(request.form['fname']):
            flash("First Name cannot contain numbers!")
            isform_valid = False
        # check if name has 3 or more char 
        if len(request.form['lname']) < 3:
            flash(" First Name should have more than two characters")
            isform_valid= False
        # check if name matches regex
        if not NAME_REGEX.match(request.form['lname']):
            flash("Last Name cannot contain numbers!")
            isform_valid = False
        #Check length of pwd is >=8 
        if len (request.form['password']) < 8:
            flash("password should be atleast 8 characters")
            isform_valid = False
        # check if password has one capital letter and one no
        passWdString = request.form['password'] 
        print "passWdString: ", passWdString
        if not (any(x.isupper() for x in passWdString) ):
            print passWdString + " passWdString is not a valid password"
            flash("Password should have at least one capital letter ")
            isform_valid = False
        # check if password has one no
        if not(any(x.isdigit() for x in passWdString)):
            flash("Password should have at least one digit")
            isform_valid = False
        ''' 
        #To check psswd has one lower, one upper char and one digit and len is >=8 
        # if (any(x.isupper() for x in passWdString) and any(x.islower() for x in passWdString) and any(x.isdigit() for x in passWdString) and len(s) >= 7):   
        # if not Password_REGEX.match(request.form['password']):
        #     flash("Password should have at least one capital letter and one digit")
        #     isform_valid = False
        '''
        #Confirm typed pwd matches 
        if not (request.form['password']) == (request.form['password_confirmation']):
            flash("password should match")
            isform_valid= False
        #Form is sans errors  

        #-------------------------Hash your password using md5 and salt-------------------- 
        # passWdString = request.form['password']
        print "paswd as entered: ", passWdString
        salt = binascii.b2a_hex(os.urandom(15))
        print "salt", salt
        hashed_pw = md5.new(passWdString + salt).hexdigest()
        print "hashed_pw", hashed_pw
        

        #######################  INSertion query #############################
        query1 = "INSERT INTO user (first_name, last_name, email, password, hash_salt) VALUES (:first_name,:last_name, :email, :password, :salt)"
        # We'll then create a dictionary of data from the POST data received.
        data1 = {
                'first_name': request.form['fname'], 
                'last_name': request.form['lname'],
                'email': request.form['email'],
                'password': hashed_pw, 
                'salt': salt
            }
        #QUERY TO GET ALL EMAILS 
        query2 = "SELECT * FROM emails" 
        
        if (isform_valid == True and isGoodForm == 1) :
        # Run query, with dictionary values injected into the query.
            returnedUserIDfromDBInsert=mysql.query_db(query1, data1)
            print "returnedUserIDfromDBInsert: ", returnedUserIDfromDBInsert
            #store the id in session 
            session['id'] =  returnedUserIDfromDBInsert
            #QUERY TO GET ALL EMAILS 
            emailList = mysql.query_db(query2) 
            print emailList
            flash("A valid Email was successfully entered!")
            return redirect('/')
        elif(isform_valid == False):
            return redirect('/')

@app.route('/login', methods=['POST'] )
def login():
    isform_valid = True
    email = request.form['email']
    password = request.form['password']
    user_query = "SELECT * FROM user WHERE email = :email LIMIT 1"
    query_data = {'email': email}
    user = mysql.query_db(user_query, query_data)
    if len(user) != 0:
        encrypted_password = md5.new(password + user[0]['hash_salt']).hexdigest()
    if user[0]['password'] == encrypted_password:
    # this means we have a successful login!
        flash("Successfully Logged In!")
    # check if password has one Uppercase letter
    passWdString = request.form['password'] 
    print "passWdString: ", passWdString
    if not (any(x.isupper() for x in passWdString) ):
        print passWdString + " passWdString is not a valid password"
        flash("Password should have at least one capital letter ")
        isform_valid = False
    # check if password has one no
    if not(any(x.isdigit() for x in passWdString)):
        flash("Password should have at least one digit")
        isform_valid = False
    # invalid email!
    if not EMAIL_REGEX.match(request.form['email']) and len(request.form['email']) < 1:
        flash("Invalid Email Address!")
        isform_valid = False
    
    #-----------Redirect to either the login home or user homepage-----
    if isform_valid == True:
        return redirect('/welcome')
    elif isform_valid == False:
        return redirect('/')
      
app.run(debug=True)
    