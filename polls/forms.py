from django import forms
from . import models
from django.db.models import QuerySet
from django.core import validators
from django.utils.translation import gettext as _
from django.core.exceptions import ObjectDoesNotExist
from polls import db_requests


class VehiclesFilterForm(forms.Form):
    PRICE_MIN = 0
    PRICE_MAX = 999999999

    def mark_choice():
        return  [(-1, "Any")] + [ (mark["id"], mark["name"]) for mark in db_requests.execQuery(db_requests.filter("marks")) ]

    def type_choice():
        return  [(-1, "Any")] + [ (type["id"], type["name"]) for type in db_requests.execQuery(db_requests.filter("types")) ]

    mark = forms.TypedChoiceField(coerce=int, empty_value=-1, required=False, choices=mark_choice)
    type = forms.TypedChoiceField(coerce=int, empty_value=-1, required=False, choices=type_choice)
    price_from = forms.IntegerField(required=False, validators=[validators.MinValueValidator(PRICE_MIN), validators.MaxValueValidator(PRICE_MAX)])
    price_to = forms.IntegerField(required=False, validators=[validators.MinValueValidator(PRICE_MIN), validators.MaxValueValidator(PRICE_MAX)])

    def get_results(self, result):
        try:
            cleaned_data = self.cleaned_data
        except:
            return result


        mark=cleaned_data['mark']
        if mark != -1:
            result = db_requests.filter(result, id_mark=mark)
            
        type=cleaned_data["type"]
        if type != -1:
            result = db_requests.filter(result, id_type=type)

        price_from=cleaned_data["price_from"]
        if price_from == None:
            price_from = VehiclesFilterForm.PRICE_MIN

        price_to=cleaned_data["price_to"]
        if price_to == None:
            price_to = VehiclesFilterForm.PRICE_MAX

        result = db_requests.between(result, "price", price_from, price_to)
 
        return result


class VehiclesSearchForm(forms.Form):
    search = forms.CharField(max_length=128, required=False)

    def get_results(self, result):
        try:
            cleaned_data = self.cleaned_data
        except:
            return result

        search = cleaned_data['search']
        if search != None:
            result = db_requests.search(result, model=search+"%%")
        return result


class VehiclesOrderForm(forms.Form):
    FIELDS = [
        "model",
        "price"
    ]

    def get_order_choice():
        return [ (value, value) for value in VehiclesOrderForm.FIELDS ]

    order = forms.ChoiceField(required=False, choices=get_order_choice)

    def get_results(self, result):
        try:
            cleaned_data = self.cleaned_data
        except:
            return result

        order = cleaned_data['order']
        if order != '':
            result = db_requests.orderBy(result, order)
        return result


class ReviewCreateForm(forms.Form):
    def vehicle_choice():
        return  [ (vehicle["id"], vehicle["model"]) for vehicle in db_requests.execQuery(db_requests.filter("vehicles")) ]
    
    vehicle = forms.TypedChoiceField(coerce=int, empty_value=None, required=False, choices=vehicle_choice)
    review = forms.CharField(label=_("review"), max_length=1024, widget=forms.Textarea)

    table = "reviews"

    def get_review(self):
        return self.cleaned_data["review"]

    def get_vehicle(self):
        return self.cleaned_data["vehicle"]
