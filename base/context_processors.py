from django.http import HttpResponse
from django.template import RequestContext, Template
from DreamService import settings
from polls import db_requests

def user_processor(request):
    user = request.session.get(settings.SESSION_USER_KEY, None)
    if user != None:
        user = db_requests.execQuery(db_requests.filter("users", id=user))[0]
    return {"ActiveUser": user}