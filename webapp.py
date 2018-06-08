from flask import Flask, redirect, url_for, session, request, jsonify, Markup
from flask_oauthlib.client import OAuth
from flask import render_template
#please work 
import pprint
import os
import json
from bson.objectid import ObjectId
import pymongo
 
 
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)

app.debug = True #Change this to False for production

app.secret_key = os.environ['SECRET_KEY'] #used to sign session cookies
oauth = OAuth(app)

url = 'mongodb://{}:{}@{}:{}/{}'.format(
        os.environ["MONGO_USERNAME"],
        os.environ["MONGO_PASSWORD"],
        os.environ["MONGO_HOST"],
        os.environ["MONGO_PORT"],
        os.environ["MONGO_DBNAME"])
client = pymongo.MongoClient(url)
db = client[os.environ["MONGO_DBNAME"]]
collection = db['collection']

#Set up GitHub as OAuth provider
github = oauth.remote_app(
    'github',
    consumer_key=os.environ['GITHUB_CLIENT_ID'], #your web app's "username" for github's OAuth
    consumer_secret=os.environ['GITHUB_CLIENT_SECRET'],#your web app's "password" for github's OAuth
    request_token_params={'scope': 'user:email'}, #request read-only access to the user's email.  For a list of possible scopes, see developer.github.com/apps/building-oauth-apps/scopes-for-oauth-apps
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',  
    authorize_url='https://github.com/login/oauth/authorize' #URL for github's OAuth login
)


#use a JSON file to store the past posts.  A global list variable doesn't work when handling multiple requests coming in and being handled on different threads
#Create and set a global variable for the name of you JSON file here.  The file will be created on Heroku, so you don't need to make it in GitHub
file = 'postData.json'
os.system("echo '[]'>" + file)
def loadData(newData):
#here we need to load in the database such that the data returned will be appended to the db
    print(newData)
    try:
        with open('postData.json','r+') as f:
            data = json.load(f)
            data.append(newData)
            f.seek(0)
            f.truncate()
            json.dump(data,f)
    except:
        print("Error Loading Data")
    db.collection.insert({"posts":newData})
    
@app.context_processor
def inject_logged_in():
    return {"logged_in":('github_token' in session)}

@app.route('/')
def home():
    log = False
    if 'user_data' in session:
        log = True
    return render_template('home.html', past_posts=posts_to_html(), loggedIn = log)

@app.route('/delete', methods=['POST'])
def delete():
    id = ObjectId(request.form['delete'])
    print(id)
    print(db.collection.delete_one({'_id':id}))
    return home()
	
def posts_to_html():
    ret = ""
    ret +=  Markup("<table> <tr> <th>UserName</th> <th>Post</th> <th>Delete</th></tr>")
	
    for i in collection.find():
        s = str(i['_id'])
        if 'user_data' in session:
            ret += Markup("<tr> <td>" + i['posts'][0] +  "</td> <td>" +i['posts'][1] + "</td></tr> <th><form action = \"/delete\" method = \"post\"> <button type=\"submit\" name=\"delete\" value=\"" + s + "\">Delete</button></form></th>")
        else: 
            ret += Markup("<tr> <td>" + i['posts'][0] +  "</td> <td>" +i['posts'][1] + "</td><td></td>")
    #try:
    #here we have to get data from the database such that it is readable to the html 
    #    with open('postData.json','r') as f:
    #        data = json.load(f)
    #        for i in data:
    #            print(i)
    #            ret += Markup("<tr> <td>" + i[0] +  "</td> <td>" +i[1] + "</td></tr>") 
    #except:
    #    print("error")
    ret += Markup("</table>")
    print(ret)
    
    return ret
            
            

@app.route('/posted', methods=['POST'])
def post():
    #print(session['user_data'])
    print(request.form['message'])
    message = [str(session['user_data']['login']),request.form['message']]
    loadData(message)
    return home()
    
    #This function should add the new post to the JSON file of posts and then render home.html and display the posts.  
    #Every post should include the username of the poster and text of the post. 

#redirect to GitHub's OAuth page and confirm callback URL
@app.route('/login')
def login():   
    return github.authorize(callback=url_for('authorized', _external=True, _scheme='http')) #callback URL must match the pre-configured callback URL

@app.route('/logout')
def logout():
    session.clear()
    return render_template('message.html', message='You were logged out')

@app.route('/login/authorized')
def authorized():
    resp = github.authorized_response()
    if resp is None:
        session.clear()
        message = 'Access denied: reason=' + request.args['error'] + ' error=' + request.args['error_description'] + ' full=' + pprint.pformat(request.args)      
    else:
        try:
            session['github_token'] = (resp['access_token'], '') #save the token to prove that the user logged in
            session['user_data']=github.get('user').data
            message='You were successfully logged in as ' + session['user_data']['login']
        except Exception as inst:
            session.clear()
            print(inst)
            message='Unable to login, please try again.  '
    return render_template('message.html', message=message)

#the tokengetter is automatically called to check who is logged in.
@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')


if __name__ == '__main__':
    app.run()
