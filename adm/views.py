from django.shortcuts import render
from django.views import generic
from . import models
from django.urls import reverse_lazy
from . import forms
from django.shortcuts import get_object_or_404
from DreamService import settings
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from polls import db_requests
from django.shortcuts import redirect


class AdminView(generic.TemplateView):

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)


class AdminUserCreateView(generic.FormView):
    form_class = forms.AdminUserCreateForm

    def get_success_url(self):
        return reverse_lazy("adm:users")

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminUserUpdateView(generic.FormView):
    form_class = forms.AdminUserUpdateForm

    def get_success_url(self):
        return reverse_lazy("adm:users")

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, id, *args, **kwargs)

    def get_initial(self):
        id = self.kwargs['id']
        user = db_requests.execQuery(db_requests.filter("users", id=id))[0]
        return dict(id=user["id"], email=user["email"], first_name=user["first_name"], last_name=user["last_name"], id_role=user["id_role"])

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminUsersView(generic.TemplateView):
    table = "users"

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["users"] = db_requests.execQuery(db_requests.filter("users"))
        return context


class AdminUserDeleteView(generic.RedirectView):
    table = "users"

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        db_requests.execQuery(db_requests.deleteFromTable("users", id))
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return self.request.META.get('HTTP_REFERER', settings.HOME_URL)


class AdminJobCreateView(generic.FormView):
    form_class = forms.AdminJobCreateForm

    def get_success_url(self):
        return reverse_lazy("adm:jobs")

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminJobUpdateView(generic.FormView):
    form_class = forms.AdminJobUpdateForm

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, id, *args, **kwargs)

    def get_success_url(self):
        return reverse_lazy("adm:jobs")

    def get_initial(self):
        id = self.kwargs['id']
        job = db_requests.execQuery(db_requests.filter("jobs", id=id))[0]
        return dict(id=job["id"], 
            name=job["name"],
            salary=job["salary"]
        )

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminJobsView(generic.TemplateView):
    table = "jobs"

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["jobs"] = db_requests.execQuery(db_requests.filter("jobs"))
        return context


class AdminJobDeleteView(generic.RedirectView):
    table = "jobs"

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        db_requests.execQuery(db_requests.deleteFromTable("jobs", id))
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return self.request.META.get('HTTP_REFERER', settings.HOME_URL)


class AdminTypeCreateView(generic.FormView):
    form_class = forms.AdminTypeCreateForm

    def get_success_url(self):
        return reverse_lazy("adm:types")

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminTypeUpdateView(generic.FormView):
    form_class = forms.AdminTypeUpdateForm

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, id, *args, **kwargs)

    def get_success_url(self):
        return reverse_lazy("adm:types")

    def get_initial(self):
        id = self.kwargs['id']
        type = db_requests.execQuery(db_requests.filter("types", id=id))[0]
        return dict(id=type["id"], 
            name=type["name"]
        )

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminTypesView(generic.TemplateView):
    table = "types"

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["types"] = db_requests.execQuery(db_requests.filter("types"))
        return context


class AdminTypeDeleteView(generic.RedirectView):
    table = "types"

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        db_requests.execQuery(db_requests.deleteFromTable("types", id))
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return self.request.META.get('HTTP_REFERER', settings.HOME_URL)


class AdminMarkCreateView(generic.FormView):
    form_class = forms.AdminMarkCreateForm

    def get_success_url(self):
        return reverse_lazy("adm:marks")

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminMarkUpdateView(generic.FormView):
    form_class = forms.AdminMarkUpdateForm

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, id, *args, **kwargs)

    def get_success_url(self):
        return reverse_lazy("adm:marks")

    def get_initial(self):
        id = self.kwargs['id']
        mark = db_requests.execQuery(db_requests.filter("marks", id=id))[0]
        return dict(id=mark["id"], 
            name=mark["name"]
        )

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminMarksView(generic.TemplateView):
    table = "marks"

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["marks"] = db_requests.execQuery(db_requests.filter("marks"))
        return context


class AdminMarkDeleteView(generic.RedirectView):
    table = "marks"

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        db_requests.execQuery(db_requests.deleteFromTable("marks", id))
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return self.request.META.get('HTTP_REFERER', settings.HOME_URL)



class AdminVehicleCreateView(generic.FormView):
    form_class = forms.AdminVehicleCreateForm

    def get_success_url(self):
        return reverse_lazy("adm:vehicles")

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminVehicleUpdateView(generic.FormView):
    form_class = forms.AdminVehicleUpdateForm

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, id, *args, **kwargs)

    def get_success_url(self):
        return reverse_lazy("adm:vehicles")

    def get_initial(self):
        id = self.kwargs['id']
        vehicle = db_requests.execQuery(db_requests.filter("vehicles", id=id))[0]
        return dict(id=vehicle["id"], 
            id_branch=vehicle["id_branch"],
            id_mark=vehicle["id_mark"],
            id_type=vehicle["id_type"],
            model=vehicle["model"],
            price=vehicle["price"],
            is_available=vehicle["is_available"]
        )

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminVehiclesView(generic.TemplateView):
    table = "vehicles"

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["vehicles"] = db_requests.execQuery(db_requests.filter("vehicles"))
        return context


class AdminVehicleDeleteView(generic.RedirectView):
    table = "vehicles"

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        db_requests.execQuery(db_requests.deleteFromTable("vehicles", id))
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return self.request.META.get('HTTP_REFERER', settings.HOME_URL)


class AdminInsuranceCreateView(generic.FormView):
    form_class = forms.AdminInsuranceCreateForm

    def get_success_url(self):
        return reverse_lazy("adm:insurances")

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminInsuranceUpdateView(generic.FormView):
    form_class = forms.AdminInsuranceUpdateForm

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, id, *args, **kwargs)

    def get_success_url(self):
        return reverse_lazy("adm:insurances")

    def get_initial(self):
        id = self.kwargs['id']
        insurance = db_requests.execQuery(db_requests.filter("insurances", id=id))[0]
        return dict(id=insurance["id"], 
            id_vehicle=insurance["id_vehicle"],
            insurance_start=insurance["insurance_start"],
            insurance_end=insurance["insurance_end"],
            info=insurance["info"]
        )

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminInsurancesView(generic.TemplateView):
    table = "insurances"

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["insurances"] = db_requests.execQuery(db_requests.filter("insurances"))
        return context


class AdminInsuranceDeleteView(generic.RedirectView):
    table = "insurances"

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] == 1:
            raise PermissionDenied()
        db_requests.execQuery(db_requests.deleteFromTable("insurances", id))
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return self.request.META.get('HTTP_REFERER', settings.HOME_URL)


class AdminBranchCreateView(generic.FormView):
    form_class = forms.AdminBranchCreateForm

    def get_success_url(self):
        return reverse_lazy("adm:branches")

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminBranchUpdateView(generic.FormView):
    form_class = forms.AdminBranchUpdateForm

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, id, *args, **kwargs)

    def get_success_url(self):
        return reverse_lazy("adm:branches")

    def get_initial(self):
        id = self.kwargs['id']
        branch = db_requests.execQuery(db_requests.filter("branches", id=id))[0]
        return dict(id=branch["id"], 
            address=branch["address"]
        )

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminBranchesView(generic.TemplateView):
    table = "branches"

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["branches"] = db_requests.execQuery(db_requests.filter("branches"))
        return context


class AdminBranchDeleteView(generic.RedirectView):
    table = "branches"

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        db_requests.execQuery(db_requests.deleteFromTable("branches", id))
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return self.request.META.get('HTTP_REFERER', settings.HOME_URL)


class AdminEmployeeCreateView(generic.FormView):
    form_class = forms.AdminEmployeeCreateForm

    def get_success_url(self):
        return reverse_lazy("adm:employees")

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminEmployeeUpdateView(generic.FormView):
    form_class = forms.AdminEmployeeUpdateForm

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, id, *args, **kwargs)

    def get_success_url(self):
        return reverse_lazy("adm:employees")

    def get_initial(self):
        id = self.kwargs['id']
        employee = db_requests.execQuery(db_requests.filter("employees", id=id))[0]
        return dict(id=employee["id"], 
            id_user=employee["id_user"],
            id_branch=employee["id_branch"],
            id_job=employee["id_job"]
        )

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class AdminEmployeesView(generic.TemplateView):
    table = "employees"

    def dispatch(self, request, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["employees"] = db_requests.execQuery(db_requests.filter("employees"))
        return context


class AdminEmployeeDeleteView(generic.RedirectView):
    table = "employees"

    def dispatch(self, request, id, *args, **kwargs):
        if request.session.get(settings.SESSION_USER_KEY) == None:
            return redirect("authentication:login")
        if db_requests.execQuery(db_requests.filter("users", id=request.session.get(settings.SESSION_USER_KEY)))[0]["id_role"] != 3:
            raise PermissionDenied()
        db_requests.execQuery(db_requests.deleteFromTable("employees", id))
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return self.request.META.get('HTTP_REFERER', settings.HOME_URL)

# Create your views here.
