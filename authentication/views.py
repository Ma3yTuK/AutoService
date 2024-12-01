from django.shortcuts import render
from django.views import generic
from . import models
from django.urls import reverse_lazy
from . import forms
from django.shortcuts import get_object_or_404
from DreamService import settings
from django.core.exceptions import ObjectDoesNotExist
from polls import db_requests
from django.shortcuts import redirect


class UserUpdateView(generic.FormView):
    form_class = forms.UserUpdateForm

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self):
        return self.request.GET.get('next', settings.HOME_URL)

    def get_initial(self):
        id = self.request.session[settings.SESSION_USER_KEY]
        user = db_requests.execQuery(db_requests.filter("users", id=id))[0]
        return dict(id=user["id"], email=user["email"], password1=user["password"], password2=user["password"], first_name=user["first_name"], last_name=user["last_name"], id_role=user["id_role"])

    #def get_initial(self):
    #    id = self.request.session[settings.SESSION_USER_KEY]
    #    user = db_requests.execQuery(db_requests.filter("users", id=id))[0]
    #    return dict(id=user["id"], email=user["email"], password1=user["password"], password2=user["password"], first_name=user["first_name"], last_name=user["last_name"], id_role=user["id_role"])

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class UserCreateView(generic.FormView):
    form_class = forms.UserCreateForm

    def get_success_url(self):
        return self.request.GET.get('next', settings.HOME_URL)

    def form_valid(self, form):
        form.save()
        self.request.session[settings.SESSION_USER_KEY] = form.get_user()
        return super().form_valid(form)


class AuthenticateView(generic.FormView):
    form_class = forms.AuthenticationForm

    def get_success_url(self):
        return self.request.GET.get('next', settings.HOME_URL)

    def form_valid(self, form):
        self.request.session[settings.SESSION_USER_KEY] = form.get_user()
        return super().form_valid(form)


class LogoutView(generic.RedirectView):

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        del self.request.session[settings.SESSION_USER_KEY]
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return self.request.META.get('HTTP_REFERER', settings.HOME_URL)


# Create your views here.
