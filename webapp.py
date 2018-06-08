from flask import Flask, redirect, url_for, session, request, jsonify, Markup, render_template
from flask_oauthlib.client import OAuth
from bson.objectid import ObjectId

import pprint
import os
import json
import pymongo
import sys

app = Flask(__name__)

app.debug = True #Change this to False for production

app.secret_key = os.environ['SECRET_KEY'] #used to sign session cookies
oauth = OAuth(app)

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

url = 'mongodb://{}:{}@{}:{}/{}'.format(
        os.environ["MONGO_USERNAME"],
        os.environ["MONGO_PASSWORD"],
        os.environ["MONGO_HOST"],
        os.environ["MONGO_PORT"],
        os.environ["MONGO_DBNAME"])
client = pymongo.MongoClient(url)
db = client[os.environ["MONGO_DBNAME"]]
posts = db['posts']

def update_posts(post):
    db.posts.insert({"username":post[0], "post":post[1]})
    
@app.context_processor
def inject_logged_in():
    return {"logged_in":('github_token' in session)}

@app.route('/')
def home():
    return render_template('home.html', past_posts=posts_to_html())

@app.route('/delete', methods=['POST'])
def delete():
    id = ObjectId(request.form['delete'])
    db.posts.delete_one({'_id':id})
    return render_template('home.html', past_posts=posts_to_html())
	
def posts_to_html():
    pth =  Markup("<br><table class='table table-bordered'><tr><th>User</th><th>Post</th><th></th></tr>")
    for i in posts.find():
        q = str(i['_id'])
        if 'user_data' in session:
            pth += Markup("<tr><td>" + i['username'] + "</td> <td>" +i['post'] + "<form action = \"/delete\" method = \"post\"> <button type=\"submit\" name=\"delete\" value=\"" + q + "\">delete</button></form></th></tr></th>")
        else: 
            pth += Markup("<tr><td>" + i['username'] + "</td> <td>" +i['post'] + "</td></tr>")
    pth += Markup("</table>")
    return pth
            
@app.route('/posted', methods=['POST'])
def post():
    print(request.form['message'])
    message = [str(session['user_data']['login']),request.form['message']]
    update_posts(message)
    return home()

@app.route('/login')
def login():   
    return github.authorize(callback=url_for('authorized', _external=True, _scheme='https')) #callback URL must match the pre-configured callback URL

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
