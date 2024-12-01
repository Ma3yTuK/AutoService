from django import forms
from django.utils.translation import gettext as _
from django.contrib.auth.hashers import make_password, check_password
from polls import db_requests


class UserUpdateForm(forms.Form):
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
        'exists': _("A user with this email already exists."),
    }

    id = forms.IntegerField(disabled=True, widget=forms.HiddenInput())
    email = forms.CharField(label=_("email"), max_length=128)
    password1 = forms.CharField(label=_("password"), widget=forms.PasswordInput, required=False)
    password2 = forms.CharField(label=_("password confirmation"), widget=forms.PasswordInput, required=False)
    first_name = forms.CharField(label=_("first name"), max_length=32)
    last_name = forms.CharField(label=_("last name"), max_length=32)

    def clean(self):
        cleaned_data = super().clean()

        # Retain initial values for fields not included in the form submission
        for name in self.fields:
            if not self[name].html_name in self.data and self.fields[name].initial is not None:
                cleaned_data[name] = self.fields[name].initial

        # Password validation
        if cleaned_data['password1'] or cleaned_data['password2']:
            if cleaned_data['password1'] != cleaned_data['password2']:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'],
                    code='password_mismatch',
                )

        # Check for email uniqueness
        users = db_requests.execQuery(db_requests.filter("users", email=cleaned_data["email"]))
        if users and users[0]["id"] != cleaned_data["id"]:
            raise forms.ValidationError(
                self.error_messages['exists'],
                code='exists',
            )
        return cleaned_data

    def save(self):
        cleaned_data = self.cleaned_data
        password = make_password(cleaned_data["password1"]) if cleaned_data["password1"] else None

        db_requests.execQuery(db_requests.updateTable("users", cleaned_data["id"],
            email=cleaned_data["email"],
            password=password,
            first_name=cleaned_data["first_name"],
            last_name=cleaned_data["last_name"]
        ))


class UserCreateForm(forms.Form):
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
        'exists': _("User with this email already exists."),
    }
    email = forms.CharField(label=_("email"), max_length=256)
    password1 = forms.CharField(label=_("password"), widget=forms.PasswordInput)
    password2 = forms.CharField(label=_("password confirmation"), widget=forms.PasswordInput)
    first_name = forms.CharField(label=_("first name"), max_length=32)
    last_name = forms.CharField(label=_("last name"), max_length=32)

    def clean(self):
        cleaned_data = super().clean()

        if cleaned_data['password1'] != cleaned_data['password2']:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )

        if db_requests.execQuery(db_requests.filter("users", email=cleaned_data["email"])):
            raise forms.ValidationError(
                self.error_messages['exists'],
                code='exists',
            )

        return cleaned_data

    def save(self):
        cleaned_data = self.cleaned_data
        hashed_password = make_password(cleaned_data["password1"])

        db_requests.execQuery(db_requests.insertIntoTable("users",
            email=cleaned_data["email"],
            password=hashed_password,
            first_name=cleaned_data["first_name"],
            last_name=cleaned_data["last_name"]
        ))

    def get_user(self):
        users = db_requests.execQuery(db_requests.filter("users", email=self.cleaned_data["email"]))
        return users[0]["id"]


class AuthenticationForm(forms.Form):
    error_messages = {
        'invalid_login': _("Please enter a correct email and password. Note that both fields may be case-sensitive."),
        'inactive': _("This account is inactive."),
    }
    email = forms.CharField(label=_("email"), max_length=256)
    password = forms.CharField(label=_("Password"), widget=forms.PasswordInput)

    def clean(self):
        email = self.cleaned_data.get('email')
        raw_password = self.cleaned_data.get('password')

        users = db_requests.execQuery(db_requests.filter("users", email=email))
        if not users or not check_password(raw_password, users[0]["password"]):
            raise forms.ValidationError(
                self.error_messages['invalid_login'],
                code='invalid_login',
            )

        self.user_data = users[0]
        return self.cleaned_data

    def get_user(self):
        return self.user_data["id"]