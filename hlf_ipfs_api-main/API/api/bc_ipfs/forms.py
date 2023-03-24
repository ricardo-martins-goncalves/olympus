from django import forms
from django.core.validators import RegexValidator



class CreateForm(forms.Form):
    id = forms.IntegerField(max_value=1000000)
    name = forms.CharField(label='Full Name\n', max_length=100)
    email = forms.EmailField()
    phone = forms.CharField(label='Phone Number', max_length=25)
    birthday = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    address = forms.CharField(label='Address', max_length=200)
    consent = forms.BooleanField(label='Privacy Policy Consent')


class ReadForm(forms.Form):
    id = forms.IntegerField(max_value=1000000)
    file = forms.FileField(label='Private Key File')


class DeleteForm(forms.Form):
    id = forms.IntegerField(max_value=1000000)
    file = forms.FileField(label='Private Key File')


class UpdateForm(forms.Form):
    id = forms.IntegerField(max_value=1000000)
    name = forms.CharField(label='Full Name\n', max_length=100)
    email = forms.EmailField()
    phone = forms.CharField(label='Phone Number', max_length=25)
    birthday = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    address = forms.CharField(label='Address', max_length=200)
    consent = forms.BooleanField(label='Privacy Policy Consent')
    file = forms.FileField(label='Private Key File')


class ChangePasswordForm(forms.Form):
    id = forms.IntegerField(max_value=1000000)
    file = forms.FileField(label='Private Key File')


class ListAllForm(forms.Form):
    id = forms.IntegerField(max_value=1000000)
    file = forms.FileField(label='Private Key File')


class ReadAdminForm(forms.Form):
    user_id = forms.IntegerField(max_value=1000000, label='User ID')
    admin_id = forms.IntegerField(max_value=1000000, label='Admin ID')
    file = forms.FileField(label='Admin Private Key File')


class ListAllFieldForm(forms.Form):
    admin_id = forms.IntegerField(max_value=1000000, label='Admin ID')
    file = forms.FileField(label='Private Key File')

    name = forms.BooleanField(label='Name', required=False)
    email = forms.BooleanField(label='E-mail', required=False)
    address = forms.BooleanField(label='Address', required=False)
    phone = forms.BooleanField(label='Phone Number', required=False)
    public_key = forms.BooleanField(label='Public Key', required=False)
    id = forms.BooleanField(label='ID', required=False)
    timestamp = forms.BooleanField(label='Timestamp', required=False)
    cid = forms.BooleanField(label='IPFS CID', required=False)
    hash = forms.BooleanField(label='Hash', required=False)

class ControllerUpdateForm(forms.Form):
    id = forms.IntegerField(label='User ID', max_value=1000000)
    name = forms.CharField(label='Full Name\n', max_length=100)
    email = forms.EmailField()
    phone = forms.CharField(label='Phone Number', max_length=25)
    birthday = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    address = forms.CharField(label='Address', max_length=200)
    consent = forms.BooleanField(label='Privacy Policy Consent')
    controller_id = forms.IntegerField(label='Controller ID',max_value=1000000)
    file = forms.FileField(label='Private Key File')

class ControllerReadDeleteForm(forms.Form):
    user_id = forms.IntegerField(label='User ID', max_value=1000000)
    controller_id = forms.IntegerField(label='Controller ID',max_value=1000000)
    file = forms.FileField(label='Private Key File')

class ControllerAdminPasswordForm(forms.Form):
    admin_id = forms.IntegerField(label='Admin to update Password', max_value=1000000)
    controller_id = forms.IntegerField(label='Controller ID',max_value=1000000)
    file = forms.FileField(label='Private Key File')


class DeleteSurvey(forms.Form):
    survey_id = forms.CharField(label='Survey id', max_length=25)
    id = forms.IntegerField(max_value=1000000)
    file = forms.FileField(label='Private Key File')


class SurveyForm(forms.Form):
    def __init__(self, poll, *args, **kwargs):
        super(SurveyForm, self).__init__(*args, **kwargs)
        # now we can add fields using a dictionary!
        for question in poll:
            field = forms.CharField(max_length=200)
            self.fields[f'{question}'] = field

    user_id = forms.IntegerField(label='User ID', max_value=1000000)
    file = forms.FileField(label='Private Key File')
    consent = forms.BooleanField(label='You agree with terms and conditions')

class ControllerSurveyForm(forms.Form):
    def __init__(self, poll, *args, **kwargs):
        super(ControllerSurveyForm, self).__init__(*args, **kwargs)
        # now we can add fields using a dictionary!
        for question in poll:
            field = forms.CharField(max_length=200)
            self.fields[f'{question}'] = field

    user_id = forms.IntegerField(label='User ID', max_value=1000000)
    consent = forms.BooleanField(label='You agree with terms and conditions')
    admin_id = forms.IntegerField(label='Admin ID', max_value=1000000)
    file = forms.FileField(label='Private Key File')


class SelectSurveyForm(forms.Form):
    def __init__(self, poll, *args, **kwargs):
        super(SelectSurveyForm, self).__init__(*args, **kwargs)
        for question in poll:
            field = forms.BooleanField(required=False, help_text=question['description'])
            print(question)
            self.fields[f'{question["ID"]}'] = field
    admin_id = forms.IntegerField(label='Processor ID', max_value=1000000)
    file = forms.FileField(label='Private Key File')

class CreateSurveyForm(forms.Form):
    controller_id = forms.IntegerField(max_value=1000000)
    file = forms.FileField(label='Private Key File')

    survey_id = forms.CharField(label='Survey ID', max_length=25)
    description = forms.CharField(label='Description', max_length=500)
    fields = forms.CharField(label = 'Fields separated by ";"', max_length=100)
    duration = forms.DurationField()


class ControllerRemoveParticipation(forms.Form):
    user_id = forms.IntegerField(max_value=1000000, label='User ID')
    survey_id = forms.CharField(max_length=25, label='Survey ID')
    admin_id = forms.IntegerField(max_value=1000000, label='Admin ID')
    file = forms.FileField(label='Admin Private Key File')








