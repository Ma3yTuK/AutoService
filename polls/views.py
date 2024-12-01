from django.shortcuts import render
from django.views import generic
from . import models
from django.urls import reverse_lazy
from . import forms
from django.urls import reverse
from DreamService import settings
import requests
from datetime import timedelta
from django.core.exceptions import ObjectDoesNotExist
from polls import db_requests
from django.shortcuts import redirect
from django.core.exceptions import PermissionDenied


class VehiclesView(generic.TemplateView):
    table = "vehicles"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        search_form = forms.VehiclesSearchForm(self.request.GET)
        filter_form = forms.VehiclesFilterForm(self.request.GET)
        order_form = forms.VehiclesOrderForm(self.request.GET)

        search_form.is_valid()
        filter_form.is_valid()
        order_form.is_valid()
        tmp = db_requests.filter("vehicles_extended", is_available=True)
        vehicles = db_requests.execQuery(search_form.get_results(order_form.get_results(filter_form.get_results(tmp))))
        context["search_form"] = search_form
        context["filter_form"] = filter_form
        context["order_form"] = order_form
        context["vehicles"] = vehicles
        return context


#class VehicleView(generic.TemplateView):
#    table = "vehicles"
#
#    def get_context_data(self, **kwargs):
#        context = super().get_context_data(**kwargs)
#        joint = db_requests.join(db_requests.join(table, "marks", "id_mark", "id"), "branches", "id_branch", "id")
#        context["vehicle"] = db_requests.execQuery(db_requests.filter(joint, id=self.kwargs["id"]))
#        return context 


class ReviewsView(generic.TemplateView):
    table = "reviews"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        joint = db_requests.join("vehicles", db_requests.join("reviews", "users", "id_user", "id"), "id", "id_vehicle")
        context["reviews"] = db_requests.execQuery(db_requests.filter(joint))
        return context


class ReviewCreateView(generic.FormView):
    form_class = forms.ReviewCreateForm
    table = "reviews"

    def get_success_url(self):
        return reverse("polls:reviews")

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        review = form.get_review()
        vehicle = form.get_vehicle()
        db_requests.execQuery(db_requests.insertIntoTable(
            "reviews",
            id_user=self.request.session[settings.SESSION_USER_KEY],
            id_vehicle=vehicle,
            review=review
        ))
        return super().form_valid(form)


class CartView(generic.TemplateView):
    table = "rents"

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        joint = db_requests.join("vehicles", "rents", "id", "id_vehicle")
        db_requests.execQuery(db_requests.updatePricesForUser(self.request.session[settings.SESSION_USER_KEY]))
        context["rents"] = db_requests.execQuery(db_requests.filter(joint, id_user=self.request.session[settings.SESSION_USER_KEY]))
        return context


class CreateRentView(generic.RedirectView):

    def get_redirect_field_name(self):
        return None

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        #if not db_requests.execQuery(db_requests.filter("rents", id_user=self.request.session[settings.SESSION_USER_KEY], rent_end=None)):
        db_requests.execQuery(db_requests.rent(request.session.get(settings.SESSION_USER_KEY), id))
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return self.request.GET.get('next', settings.HOME_URL)


class EndRentView(generic.RedirectView):

    def get_redirect_field_name(self):
        return None

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        db_requests.execQuery(db_requests.stopRent(request.session.get(settings.SESSION_USER_KEY), id))
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return self.request.GET.get('next', settings.HOME_URL)


class JournalView(generic.TemplateView):
    table = "action_journal"

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        joint = db_requests.join("action_journal", "users", "id_user", "id")
        context["actions"] = db_requests.execQuery(db_requests.filter(joint))
        return context


# Create your views here.    path("workers", views.WorkersView.as_view(template_name="authentication/workers.html"), name="workers"),

