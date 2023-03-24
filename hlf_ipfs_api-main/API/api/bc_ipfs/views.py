import re
from datetime import date, timedelta, datetime, time
from threading import Thread, Lock
import os
from webbrowser import get

from cryptography.hazmat.primitives import serialization

from api.bc_ipfs.assym_crypto import RSA as rsa
from django.http import HttpResponse, HttpResponseNotFound, HttpResponseRedirect
from django.shortcuts import render
from pathlib import Path
from api.bc_ipfs.forms import CreateForm, ReadForm, DeleteForm, UpdateForm, ChangePasswordForm, ListAllForm, \
    ReadAdminForm, \
    ListAllFieldForm, ControllerUpdateForm, ControllerReadDeleteForm, ControllerAdminPasswordForm, SurveyForm, \
    DeleteSurvey, SelectSurveyForm, CreateSurveyForm, ControllerSurveyForm, ControllerRemoveParticipation
from api.bc_ipfs.hlf_auth import Auth_HLF
from api.bc_ipfs.ipfs import IPFS
from api.bc_ipfs.hlf import HLF
from api.bc_ipfs.hlf_surveys import Surveys_HLF
from api.bc_ipfs.assym_crypto import RSA
from ast import literal_eval
import json

lock = Lock()


# Create your views here.

def root(request):
    return render(request, 'index.html')

def user(request):
    return render(request, 'user.html')

def processor(request):
    return render(request, 'processor.html')

def controller(request):
    return render(request, 'controller.html')

def surveys(request):
    return render(request, 'surveys.html')

def controller_surveys_page(request):
    return render(request, 'controller/surveys/index.html')

def get_survey_list():
    log = Surveys_HLF.get_all_surveys()
    surveys_list =[]
    if "status:200" in str(log):
        surveys = log.decode("utf-8").split("->")[1]
        if "payload:" in surveys:
            surveys = (surveys.split('"[{'))[1].split('}]"')[0].replace("\\", "")
            surveys = "[{" + surveys + "}]"
            surveys_list = json.loads(surveys)
    return surveys_list

def get_user_participation(asset_dict):
    surveys_dict = {}
    surveys_str = asset_dict['surveys']
    surveys_str_array = surveys_str.split(";")
    surveys_str_array.pop()

    for survey_str in surveys_str_array:
        tmp = survey_str.split("_")
        ipfs_string = IPFS.read_survey(tmp[1])
        surveys_dict[f'{tmp[0]}'] = [ipfs_string, tmp [1]]
    return surveys_dict




def get_survey(id):
    log = Surveys_HLF.read(id)
    survey_dict =[]
    if "status:200" in str(log):
        survey = log.decode("utf-8").split("->")[1]
        if "payload:" in survey:
            survey = (survey.split('"{'))[1].split('}"')[0].replace("\\", "")
            survey = "{" + survey + "}"
            survey_dict = json.loads(survey)
    return survey_dict


def survey_list(request):
        log = Surveys_HLF.get_all_surveys()
        if "status:200" in str(log):
            surveys = log.decode("utf-8").split("->")[1]
            if "payload:" in surveys:
                surveys = (surveys.split('"[{'))[1].split('}]"')[0].replace("\\", "")
                surveys = "[{" + surveys + "}]"
                surveys_list = json.loads(surveys)
                return render(request, 'list_surveys.html', {'Surveys': surveys_list})
            else:
                return render(request, 'fail.html', {'Info': "No survey available at this moment"})
        else:
            return render(request, 'fail.html', {'Action': "List Surveys", 'Info': log.decode()})



def add_participation_survey_list(request):
        log = Surveys_HLF.get_all_surveys()
        if "status:200" in str(log):
            surveys = log.decode("utf-8").split("->")[1]
            if "payload:" in surveys:
                surveys = (surveys.split('"[{'))[1].split('}]"')[0].replace("\\", "")
                surveys = "[{" + surveys + "}]"
                surveys_list = json.loads(surveys)
                return render(request, 'list_surveys.html', {'Surveys': surveys_list})
            else:
                return render(request, 'fail.html', {'Info': "No survey available at this moment"})
        else:
            return render(request, 'fail.html', {'Action': "List Surveys", 'Info': log.decode()})


def survey_create_update(request, survey_id):
    surveys_ids = [survey['ID'] for survey in get_survey_list()]
    if survey_id not in surveys_ids:
        return render(request, 'fail.html', {'Action': "Participate in Survey", 'Info': "The survey " + survey_id + " does not exists"})
    else:
        survey = get_survey(survey_id)
        fields = survey['Fields']
        fields = fields.split(";")
        if request.method == 'POST':
            form = SurveyForm(fields, request.POST, request.FILES)
            if form.is_valid():
                user_id = form.cleaned_data['user_id']
                #authentication
                private_key_bytes = request.FILES['file'].read()
                asset = HLF.read(form.cleaned_data['user_id']).decode("utf-8")
                if "status:200" in str(asset):
                    asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                    asset = "{" + asset + "}"
                    asset_dict = json.loads(asset)
                    if not asset_dict['deleted']:
                        cid = asset_dict['cid']
                        signature = RSA.sign(private_key_bytes, cid)
                        del private_key_bytes
                        authorization = IPFS.verify_signature(cid, signature)
                        if authorization:
                            del form.cleaned_data['user_id']
                            del form.cleaned_data['file']
                            cid, ipfs_hash = IPFS.write_survey(form.cleaned_data)
                            if survey_id in asset_dict['surveys']:
                                survey_cid = (asset_dict['surveys'].split(survey_id+"_"))[1].split(';')[0]
                                IPFS.delete(survey_cid)
                                HLF.delete_cid_from_survey(user_id, survey_id, survey_cid )
                                Surveys_HLF.remove_cid(survey_id,survey_cid)

                            log_hlf = HLF.add_cid_to_survey(user_id, survey_id,cid)
                            log_surveys = Surveys_HLF.add_cid(survey_id, cid)
                            log_hlf = log_hlf.decode("utf-8").split("->")[1]
                            log_surveys = log_surveys.decode("utf-8").split("->")[1]
                            return render(request, 'survey_success.html',
                                          {'Action': "Answer Survey",
                                           'Log1':  log_hlf, 'Log2':  log_surveys,
                                           "CID": cid})
                        else:
                            return render(request, 'fail.html',
                                          {'Action': "Participate in Survey", 'Info': "Private Key is not Valid"})
            else:
                return render(request, 'fail.html', {'Action': "Participate in the survey", 'Info': "Form is not valid", 'form':form})
        else:
            form = SurveyForm(poll=fields)
        return render(request, 'survey_form.html', {'Title': 'Survey Participation', 'form': form, 'Survey':survey })


def survey_read(request):
    if request.method == 'POST':
        form = ReadForm(request.POST, request.FILES)
        if form.is_valid():
            private_key_bytes = request.FILES['file'].read()
            asset = HLF.read(form.cleaned_data['id']).decode("utf-8")
            if "status:200" in str(asset):
                asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                asset = "{" + asset + "}"
                asset_dict = json.loads(asset)
                if not asset_dict['deleted']:
                    cid = asset_dict['cid']
                    signature = RSA.sign(private_key_bytes, cid)
                    del private_key_bytes
                    authorization = IPFS.verify_signature(cid, signature)
                    if authorization:
                        participated_surveys = get_user_participation(asset_dict)
                        return render(request, 'participated_surveys.html', {'Action': "Read Surveys", 'Surveys': participated_surveys})
                    else:
                        return render(request, 'fail.html',
                                      {'Action': "Read Surveys", 'Info': "Private Key is not Valid"})
                else:
                    return render(request, 'fail.html',
                                      {'Action': "Read Surveys", 'Info': "User has been deleted"})
            else:
                return render(request, 'fail.html', {'Action': "Read Asset", 'Info': asset})
        else:
            return render(request, 'fail.html', {'Action': "Read Surveys", 'Info': "Form is not valid"})
    else:
        form = ReadForm()
    return render(request, 'forms.html', {'Title': 'User Information', 'form': form})


def survey_delete(request):
    if request.method == 'POST':
        form = DeleteSurvey(request.POST, request.FILES)
        if form.is_valid():
            user_id = form.cleaned_data['id']
            asset = HLF.read(user_id).decode("utf-8")
            private_key_bytes = request.FILES['file'].read()
            survey_id = form.cleaned_data['survey_id']
            if "status:200" in str(asset):
                asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                asset = "{" + asset + "}"
                asset_dict = json.loads(asset)
                if not asset_dict['deleted']:
                    cid = asset_dict['cid']
                    signature = RSA.sign(private_key_bytes, cid)
                    del private_key_bytes
                    authorization = IPFS.verify_signature(asset_dict['cid'], signature)
                    if authorization:
                        surveys = get_user_participation(asset_dict)
                        if survey_id not in surveys.keys():
                            return render(request, 'success.html', {'Info': 'You have not participated in this survey, yet.'},)

                        survey_cid = (asset_dict['surveys'].split(survey_id + "_"))[1].split(';')[0]
                        result = IPFS.delete(survey_cid)
                        log_hlf = HLF.delete_cid_from_survey(user_id, survey_id, survey_cid)
                        log_surveys = Surveys_HLF.remove_cid(survey_id, survey_cid)
                        log_hlf = log_hlf.decode("utf-8")
                        log_surveys = log_surveys.decode("utf-8")
                        if result and "status:200" in str(log_hlf) and "status:200" in str(log_surveys):
                            log_hlf = log_hlf.split("->")[1]
                            log_surveys = log_surveys.split("->")[1]
                            return render(request, 'survey_success.html',
                                          {'Action': "Answer Survey",
                                           'Log1':  log_hlf, 'Log2':  log_surveys,
                                           "CID": cid})
                        else:
                            return render(request, 'fail.html',
                                          {'Action': "Delete Survey", 'Info': 'Could not delete the ipfs file'}, )

                    else:
                        return render(request, 'fail.html',
                                      {'Action': "Delete Survey, Wrong Private Key", 'Info': asset}, )
                else:
                    return render(request, 'fail.html',
                                  {'Action': "Delete Survey", 'Info': "The file was already deleted"}, )
            else:
                return render(request, 'fail.html', {'Action': "Delete Survey", 'Info': asset})
        else:
            return render(request, 'fail.html', {'Action': "Delete Survey", 'Info': "Form is not valid"})
    else:
        form = DeleteSurvey()
    return render(request, 'forms.html', {'Title': 'Survey To Delete', 'form': form})



def create(request):
    if request.method == 'POST':
        form = CreateForm(request.POST)
        if form.is_valid():
            public_key, private_key = rsa.create_key_pair()
            cid, ipfs_hash = IPFS.write(form, public_key.decode())
            id = form.cleaned_data['id']
            os.chdir(str(Path.home()) + "/API")
            with lock:
                sk = Path(f'private_keys/private_{id}.pem')
                sk.parent.mkdir(exist_ok=True, parents=True)
                with open(f'private_keys/private_{id}.pem', "wb") as sk:
                    sk.write(private_key)
            log = HLF.write(id, form.cleaned_data['consent'], cid, ipfs_hash)
            if "status:200" in str(log) and cid is not None:
                log = log.decode("utf-8").split("->")[1]
                return render(request, 'success.html',
                              {'Action': "Create User", 'Info': log, "CID": cid, 'Hash': ipfs_hash,
                               'Private_Key': private_key.decode()})
            else:
                return render(request, 'fail.html', {'Action': "Create User", 'Info': log.decode()})
        else:
            return render(request, 'fail.html', {'Action': "Create Asset", 'Info': "Form is not valid"})
    else:
        form = CreateForm()
    return render(request, 'forms.html', {'Title': 'User Information', 'form': form})


def read(request):
    if request.method == 'POST':
        form = ReadForm(request.POST, request.FILES)
        if form.is_valid():
            private_key_bytes = request.FILES['file'].read()
            asset = HLF.read(form.cleaned_data['id']).decode("utf-8")
            if "status:200" in str(asset):
                asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                asset = "{" + asset + "}"
                asset_dict = json.loads(asset)
                ipfs_hash = None
                if not asset_dict['deleted']:
                    cid = asset_dict['cid']
                    surveys_ids = asset_dict['surveys'].split(";")
                    surveys_ids.pop()
                    asset_dict['surveys'] = []
                    for survey in surveys_ids:
                        tmp = survey.split("_")[0]
                        asset_dict['surveys'].append(tmp)
                    signature = RSA.sign(private_key_bytes, cid)
                    del private_key_bytes
                    authorization = IPFS.verify_signature(cid, signature)
                    if authorization:
                        ipfs_string, ipfs_hash = IPFS.read(asset_dict['cid'])
                    else:
                        return render(request, 'fail.html',
                                      {'Action': "Read Asset", 'Info': "Private Key is not Valid"})
                else:
                    asset_dict = {"Asset Not Valid": "Deleted File"}
                    ipfs_string = '{"File":"Deleted"}'
                ipfs_dict = json.loads(ipfs_string)
                user = [asset_dict, ipfs_dict]
                if ipfs_hash is not None:
                    confirmation = asset_dict['hash'] == ipfs_hash
                    user.append(confirmation)
                    return render(request, 'read.html', {'User': user, "Hash": ipfs_hash})
                return render(request, 'read.html', {'User': user})
            else:
                return render(request, 'fail.html', {'Action': "Read Asset", 'Info': asset})
        else:
            return render(request, 'fail.html', {'Action': "Read Asset", 'Info': "Form is not valid"})
    else:
        form = ReadForm()
    return render(request, 'forms.html', {'Title': 'User', 'form': form})


def delete(request):
    if request.method == 'POST':
        form = DeleteForm(request.POST, request.FILES)
        if form.is_valid():
            asset = HLF.read(form.cleaned_data['id']).decode("utf-8")
            private_key_bytes = request.FILES['file'].read()
            if "status:200" in str(asset):
                asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                asset = "{" + asset + "}"
                asset_json = json.loads(asset)
                if not asset_json['deleted']:
                    cid = asset_json['cid']
                    signature = RSA.sign(private_key_bytes, cid)
                    del private_key_bytes
                    authorization = IPFS.verify_signature(asset_json['cid'], signature)
                    if authorization:
                        result = IPFS.delete(asset_json['cid'])
                        if result is True:
                            HLF.deleteIPFS(form.cleaned_data['id']).decode("utf-8")
                            return render(request, 'deleted.html', {'Action': "Delete Asset", 'HLF': asset_json})

                        else:
                            return render(request, 'fail.html',
                                          {'Action': "Delete Asset, This file was already deleted", 'Info': asset}, )
                    else:
                        return render(request, 'fail.html',
                                      {'Action': "Delete Asset, Wrong Private Key", 'Info': asset}, )
                else:
                    return render(request, 'fail.html',
                                  {'Action': "Delete Asset", 'Info': "The file was already deleted"}, )
            else:
                return render(request, 'fail.html', {'Action': "Delete Asset", 'Info': asset})
        else:
            return render(request, 'fail.html', {'Action': "Delete Asset", 'Info': "Form is not valid"})
    else:
        form = DeleteForm()
    return render(request, 'forms.html', {'Title': 'User To Delete', 'form': form})


def update(request):
    if request.method == 'POST':
        form = UpdateForm(request.POST, request.FILES)
        if form.is_valid():
            asset = HLF.read(form.cleaned_data['id']).decode("utf-8")
            private_key_bytes = request.FILES['file'].read()
            if "status:200" in str(asset):
                asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                asset = "{" + asset + "}"
                asset_json = json.loads(asset)
                cid = asset_json['cid']
                signature = RSA.sign(private_key_bytes, cid)
                del private_key_bytes
                authorization = IPFS.verify_signature(cid, signature)
                if authorization is None:
                    return render(request, 'fail.html', {'Action': "Update User", 'Info': 'Asset Was Deleted'})
                if authorization:
                    public_key = IPFS.get_public_key(cid)
                    result = IPFS.delete(cid)
                    cid, ipfs_hash = IPFS.write(form, public_key)
                    log = HLF.update(form.cleaned_data['id'], form.cleaned_data['consent'], cid, ipfs_hash)
                    if "status:200" in str(log) and cid is not None:
                        log = log.decode("utf-8").split("->")[1]
                        return render(request, 'success.html',
                                      {'Action': "Update User", 'Info': log, "CID": cid, 'Hash': ipfs_hash})
                    else:
                        return render(request, 'fail.html', {'Action': "Update User", 'Info': log.decode()})
                else:
                    return render(request, 'fail.html', {'Action': "Update User", 'Info': 'Wrong Private Key'})
            else:
                return render(request, 'fail.html', {'Action': "Update User", 'Info': asset})
        else:
            return render(request, 'fail.html', {'Action': "Update Asset", 'Info': "Form is not valid"})
    else:
        form = UpdateForm()
    return render(request, 'forms.html', {'Title': 'New Information', 'form': form})


def thread_read(asset_dict, users, index):
    ipfs_hash = None
    if not asset_dict['deleted']:
        ipfs_string, ipfs_hash = IPFS.read(asset_dict['cid'])
    else:
        ipfs_string = '{"File":"Deleted"}'
    ipfs_dict = json.loads(ipfs_string)
    user = [asset_dict, ipfs_dict]
    if ipfs_hash is not None:
        confirmation = asset_dict['hash'] == ipfs_hash
        user.append(confirmation)
    lock.acquire()
    users.insert(index, user)
    lock.release()

def change_password(request):
    if request.method == 'POST':
        form = ChangePasswordForm(request.POST, request.FILES)
        if form.is_valid():
            id = form.cleaned_data['id']
            asset = HLF.read(id).decode("utf-8")
            private_key_bytes = request.FILES['file'].read()
            if "status:200" in str(asset):
                asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                asset = "{" + asset + "}"
                asset_json = json.loads(asset)
                cid = asset_json['cid']
                signature = RSA.sign(private_key_bytes, cid)
                del private_key_bytes
                authorization = IPFS.verify_signature(cid, signature)
                if authorization is None:
                    return render(request, 'fail.html', {'Action': "Change Password", 'Info': 'Asset Was Deleted'})
                if authorization:
                    new_public_key, new_private_key = rsa.create_key_pair()
                    os.chdir(str(Path.home()) + "/API")
                    with lock:
                        sk = Path(f'private_keys/private_{id}_new.pem')
                        sk.parent.mkdir(exist_ok=True, parents=True)
                        with open(f'private_keys/private_{id}_new.pem', "wb") as sk:
                            sk.write(new_private_key)
                    new_cid, new_hash = IPFS.change_password(cid, new_public_key.decode())
                    log = HLF.update(id, asset_json['consents'], new_cid, new_hash)
                    if "status:200" in str(log) and new_cid is not None and new_hash is not None:
                        log = log.decode("utf-8").split("->")[1]
                        return render(request, 'success.html',
                                      {'Action': "Change Password", 'Info': log, "CID": cid,
                                       'Private_Key': new_private_key.decode()})
                    else:
                        return render(request, 'fail.html', {'Action': "Change Password", 'Info': log.decode()})
                else:
                    return render(request, 'fail.html', {'Action': "Change Password", 'Info': 'Wrong Private Key'})
            else:
                return render(request, 'fail.html', {'Action': "Change Password", 'Info': asset})
        else:
            return render(request, 'fail.html', {'Action': "Change Password", 'Info': "Form is not valid"})
    else:
        form = ChangePasswordForm()
    return render(request, 'forms.html', {'Title': 'Old Credentials', 'form': form})

### ADMIN Functions
def listall(request):
    if request.method == 'POST':
        form = ListAllForm(request.POST, request.FILES)
        if form.is_valid():
            id = form.cleaned_data['id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(id))
            del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(id, signature)
            if not sign_verification:
                return render(request, 'fail.html', {'Action': "List All Users", 'Info': 'Wrong Private Key'})
            role_response = Auth_HLF.getRole(id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "processor" and role != "controller":
                return render(request, 'fail.html', {'Action': "List All Users", 'Info': 'You are not a data controller or processor'})
            else:
                assets = HLF.get_all_assets().decode("utf-8")
                if "status:200" in str(assets):
                    users = []
                    if "payload:" in assets:
                        assets = (assets.split('"[{'))[1].split('}]"')[0].replace("\\", "")
                        assets = "[{" + assets + "}]"
                        assets_list = json.loads(assets)
                        threads = []
                        for index, asset_dict in enumerate(assets_list):
                            t = Thread(target=thread_read, args=(asset_dict, users, index))
                            threads.append(t)
                            t.start()
                        # Wait for all of them to finish
                        for x in threads:
                            x.join()
                        return render(request, 'listall.html', {'Action': "List All User", 'Users': users})
                    else:
                        return render(request, 'listall.html', {'Action': "List All User", 'Info': "System without registers yet"})
                else:
                    return render(request, 'fail.html', {'Action': "Read Asset", 'Info': assets})
        else:
            return render(request, 'fail.html', {'Action': "List All Users", 'Info': "Form is not valid"})
    else:
        form = ListAllForm()
    return render(request, 'forms.html', {'Title': 'Authentication', 'form': form})


def admin_read(request):
    if request.method == 'POST':
        form = ReadAdminForm(request.POST, request.FILES)
        if form.is_valid():
            admin_id = form.cleaned_data['admin_id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(admin_id))
            # del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(admin_id, signature)
            if not sign_verification:
                return render(request, 'fail.html', {'Action': "List All Users", 'Info': 'Wrong Private Key'})
            role_response = Auth_HLF.getRole(admin_id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "processor" and role != "controller":
                return render(request, 'fail.html',
                              {'Action': "List All Users", 'Info': 'You are not a data controller or processor'})
            else:
                asset = HLF.read(form.cleaned_data['user_id']).decode("utf-8")
                if "status:200" in str(asset):
                    asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                    asset = "{" + asset + "}"
                    asset_dict = json.loads(asset)
                    ipfs_hash = None
                    if not asset_dict['deleted']:
                        ipfs_string, ipfs_hash = IPFS.read(asset_dict['cid'])
                    else:
                        ipfs_string = '{"File":"Deleted"}'
                    ipfs_dict = json.loads(ipfs_string)
                    user = [asset_dict, ipfs_dict]
                    if ipfs_hash is not None:
                        confirmation = asset_dict['hash'] == ipfs_hash
                        user.append(confirmation)
                        return render(request, 'read.html', {'User': user, "Hash": ipfs_hash})
                    return render(request, 'read.html', {'User': user})
                else:
                    return render(request, 'fail.html', {'Action': "Read Asset", 'Info': asset})
        else:
            return render(request, 'fail.html', {'Action': "Read Asset", 'Info': "Form is not valid"})
    else:
        form = ReadAdminForm()
    return render(request, 'forms.html', {'Title': 'User', 'form': form})




def listall_survey(request):
    surveys = get_survey_list()
    if request.method == 'POST':
        form = SelectSurveyForm(surveys, request.POST, request.FILES)
        if form.is_valid():
            admin_id = form.cleaned_data['admin_id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(admin_id))
            del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(admin_id, signature)
            if not sign_verification:
                return render(request, 'fail.html', {'Action': "List All Users", 'Info': 'Wrong Private Key'})
            role_response = Auth_HLF.getRole(admin_id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "processor" and role != "controller":
                return render(request, 'fail.html',
                              {'Action': "List All Users", 'Info': 'You are not a data controller or processor'})
            else:
                del form.cleaned_data['admin_id']
                del form.cleaned_data['file']
                surveys_to_read = []
                for s in form.cleaned_data:
                    if form.cleaned_data[f'{s}']:
                        surveys_to_read.append(s)
                all_surveys = get_survey_list()
                dict_to_return = {}
                for survey in all_surveys:
                    if survey['ID'] in surveys_to_read:
                        ipfs_information = []
                        cids = survey['cids'].split(";")
                        cids.pop()
                        for cid in cids:
                            result = IPFS.read_survey(cid)
                            ipfs_information.append(IPFS.read_survey(cid))
                        list_tmp = [survey['description'], survey['dealine'], ipfs_information]
                        dict_to_return[f'{survey["ID"]}']=list_tmp
                return render(request, 'processor_listall_surveys.html', {'Action': "List Information by Field", 'Info': dict_to_return})
        else:
            return render(request, 'fail.html', {'Action': "Get Surveys", 'Info': "Form is not valid"})
    else:
        form = SelectSurveyForm(surveys)
    return render(request, 'forms.html', {'Title': 'Surveys', 'form': form})





def listall_field(request):
    if request.method == 'POST':
        form = ListAllFieldForm(request.POST, request.FILES)
        if form.is_valid():
            admin_id = form.cleaned_data['admin_id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(admin_id))
            del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(admin_id, signature)
            if not sign_verification:
                return render(request, 'fail.html', {'Action': "List All Users", 'Info': 'Wrong Private Key'})
            role_response = Auth_HLF.getRole(admin_id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "processor" and role != "controller":
                return render(request, 'fail.html',
                              {'Action': "List All Users", 'Info': 'You are not a data controller or processor'})
            else:
                assets = HLF.get_all_assets().decode("utf-8")
                if "status:200" in str(assets):
                    users = []
                    if "payload:" in assets:
                        assets = (assets.split('"[{'))[1].split('}]"')[0].replace("\\", "")
                        assets = "[{" + assets + "}]"
                        assets_list = json.loads(assets)
                        threads = []
                        fields = form.cleaned_data
                        del fields['admin_id']
                        del fields['file']
                        dict_2_return = { field:[] for field in fields}
                        for index, asset_dict in enumerate(assets_list):
                            t = Thread(target=thread_read, args=(asset_dict, users, index))
                            threads.append(t)
                            t.start()
                        # Wait for all of them to finish
                        for x in threads:
                            x.join()
                        for user in users:
                            if(user[0]['deleted'] == False):
                                if form.cleaned_data['name'] :
                                    dict_2_return['name'].append(user[1]['name'])
                                if form.cleaned_data['email']:
                                    dict_2_return['email'].append(user[1]['email'])
                                if form.cleaned_data['address']:
                                    dict_2_return['address'].append(user[1]['address'])
                                if form.cleaned_data['phone']:
                                    dict_2_return['phone'].append(user[1]['phone'])
                                if form.cleaned_data['public_key']:
                                    dict_2_return['public_key'].append(user[1]['public_key'])
                                if form.cleaned_data['id']:
                                    dict_2_return['id'].append(user[0]['ID'])
                                if form.cleaned_data['timestamp']:
                                    dict_2_return['timestamp'].append(user[0]['timestamp'])
                                if form.cleaned_data['cid']:
                                    dict_2_return['cid'].append(user[0]['cid'])
                                if form.cleaned_data['hash']:
                                    dict_2_return['hash'].append(user[0]['hash'])
                        return render(request, 'listall_field.html', {'Action': "List Information by Field", 'Fields': dict_2_return})
                    else:
                        return render(request, 'listall_field.html',
                                      {'Action': "List Information by Field", 'Info': "System without registers yet"})
                else:
                    return render(request, 'fail.html', {'Action': "List Information by Field", 'Info': assets})
        else:
            return render(request, 'fail.html', {'Action': "List Information by Field", 'Info': "Form is not valid"})
    else:
        form = ListAllFieldForm()
    return render(request, 'form_listall_field.html', {'Title': 'Fields', 'form': form})



def controller_update(request):
    if request.method == 'POST':
        form = ControllerUpdateForm(request.POST, request.FILES)
        if form.is_valid():
            admin_id = form.cleaned_data['controller_id']
            id = form.cleaned_data['id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(admin_id))
            del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(admin_id, signature)
            if not sign_verification:
                return render(request, 'fail.html', {'Action': "List All Users", 'Info': 'Wrong Private Key'})
            role_response = Auth_HLF.getRole(admin_id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "controller":
                return render(request, 'fail.html',
                              {'Action': "Update User", 'Info': 'Only Data Controller can perform this operation'})
            else:
                asset = HLF.read(form.cleaned_data['id']).decode("utf-8")
                if "status:200" in str(asset):
                    asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                    asset = "{" + asset + "}"
                    asset_json = json.loads(asset)
                    cid = asset_json['cid']
                    if not asset_json['deleted']:
                        public_key = IPFS.get_public_key(cid)
                        private_key = None
                        result = IPFS.delete(cid)
                    else:
                        public_key, private_key = rsa.create_key_pair()
                        os.chdir(str(Path.home()) + "/API")
                        with lock:
                            sk = Path(f'private_keys/private_{id}_restored.pem')
                            sk.parent.mkdir(exist_ok=True, parents=True)
                            with open(f'private_keys/private_{id}_restored.pem', "wb") as sk:
                                sk.write(private_key)
                    del form.cleaned_data['controller_id']
                    del form.cleaned_data['file']
                    new_cid, ipfs_hash = IPFS.write(form, public_key.decode())
                    log = HLF.update(form.cleaned_data['id'], form.cleaned_data['consent'], new_cid, ipfs_hash)
                    if "status:200" in str(log) and cid is not None:
                        log = log.decode("utf-8").split("->")[1]
                        if(private_key is not None):
                            return render(request, 'success.html',
                                          {'Action': "Update User", 'Info': log, "CID": cid, 'Hash': ipfs_hash, 'Private_Key': private_key.decode()})
                        else:
                            return render(request, 'success.html',
                                          {'Action': "Update User", 'Info': log, "CID": cid, 'Hash': ipfs_hash})
                    else:
                        return render(request, 'fail.html', {'Action': "Update User", 'Info': log.decode()})
                else:
                    return render(request, 'fail.html', {'Action': "Update User", 'Info': asset})
        else:
            return render(request, 'fail.html', {'Action': "Update Asset", 'Info': "Form is not valid"})
    else:
        form = ControllerUpdateForm()
    return render(request, 'forms.html', {'Title': 'New Information', 'form': form})




def controller_delete(request):
    if request.method == 'POST':
        form = ControllerReadDeleteForm(request.POST, request.FILES)
        if form.is_valid():
            admin_id = form.cleaned_data['controller_id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(admin_id))
            del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(admin_id, signature)
            if not sign_verification:
                return render(request, 'fail.html', {'Action': "List All Users", 'Info': 'Wrong Private Key'})
            role_response = Auth_HLF.getRole(admin_id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "controller":
                return render(request, 'fail.html',
                              {'Action': "Delete User", 'Info': 'Only Data Controller can perform this operation'})
            else:
                asset = HLF.read(form.cleaned_data['user_id']).decode("utf-8")
                if "status:200" in str(asset):
                    asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                    asset = "{" + asset + "}"
                    asset_json = json.loads(asset)
                    if not asset_json['deleted']:
                        result = IPFS.delete(asset_json['cid'])
                        if result is True:
                            HLF.deleteIPFS(form.cleaned_data['user_id']).decode("utf-8")
                            return render(request, 'deleted.html', {'Action': "Delete Asset", 'HLF': asset_json})
                        else:
                            return render(request, 'fail.html',
                                          {'Action': "Delete Asset, This file was already deleted", 'Info': asset}, )
                    else:
                        return render(request, 'fail.html',
                                      {'Action': "Delete Asset", 'Info': "The file was already deleted"}, )
                else:
                    return render(request, 'fail.html', {'Action': "Delete Asset", 'Info': asset})
        else:
            return render(request, 'fail.html', {'Action': "Delete Asset", 'Info': "Form is not valid"})
    else:
        form = ControllerReadDeleteForm()
    return render(request, 'forms.html', {'Title': 'User To Delete', 'form': form})




def controller_user_passwd(request):
    if request.method == 'POST':
        form = ControllerReadDeleteForm(request.POST, request.FILES)
        if form.is_valid():
            admin_id = form.cleaned_data['controller_id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(admin_id))
            del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(admin_id, signature)
            if not sign_verification:
                return render(request, 'fail.html', {'Action': "Change User Key", 'Info': 'Wrong Controller Private Key'})
            role_response = Auth_HLF.getRole(admin_id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "controller":
                return render(request, 'fail.html',
                              {'Action': "Delete User", 'Info': 'Only Data Controller can perform this operation'})
            else:
                user_id = form.cleaned_data['user_id']
                asset = HLF.read(user_id).decode("utf-8")
                if "status:200" in str(asset):
                    asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                    asset = "{" + asset + "}"
                    asset_json = json.loads(asset)
                    cid = asset_json['cid']
                    if asset_json['deleted'] is True:
                        return render(request, 'fail.html', {'Action': "Change Password", 'Info': 'Asset Was Deleted'})
                    new_public_key, new_private_key = rsa.create_key_pair()
                    os.chdir(str(Path.home()) + "/API")
                    with lock:
                        sk = Path(f'private_keys/private_{user_id}_new.pem')
                        sk.parent.mkdir(exist_ok=True, parents=True)
                        with open(f'private_keys/private_{user_id}_new.pem', "wb") as sk:
                            sk.write(new_private_key)
                    new_cid, new_hash = IPFS.change_password(cid, new_public_key.decode())
                    log = HLF.update(user_id, asset_json['consents'], new_cid, new_hash)
                    if "status:200" in str(log) and new_cid is not None and new_hash is not None:
                        log = log.decode("utf-8").split("->")[1]
                        return render(request, 'success.html',
                                      {'Action': "Change Password", 'Info': log, "CID": cid,
                                       'Private_Key': new_private_key.decode()})
                    else:
                        return render(request, 'fail.html', {'Action': "Change Password", 'Info': log.decode()})
                else:
                    return render(request, 'fail.html', {'Action': "Change Password", 'Info': asset})
        else:
            return render(request, 'fail.html', {'Action': "Delete Asset", 'Info': "Form is not valid"})
    else:
        form = ControllerReadDeleteForm()
    return render(request, 'forms.html', {'Title': 'User To Delete', 'form': form})

def controller_passwd(request):
    if request.method == 'POST':
        form = ControllerAdminPasswordForm(request.POST, request.FILES)
        if form.is_valid():
            admin_id = form.cleaned_data['controller_id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(admin_id))
            del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(admin_id, signature)
            if not sign_verification:
                return render(request, 'fail.html',
                              {'Action': "Change User Key", 'Info': 'Wrong Controller Private Key'})
            role_response = Auth_HLF.getRole(admin_id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "controller":
                return render(request, 'fail.html',
                              {'Action': "Change Admin Password", 'Info': 'Only Data Controller can perform this operation'})
            else:
                admin_id = form.cleaned_data['admin_id']
                role_response = Auth_HLF.getRole(admin_id)
                aux = re.search('payload:"(.*)"', role_response.decode())
                role = aux.group(1)
                new_public_key, new_private_key = rsa.create_key_pair()
                os.chdir(str(Path.home()) + "/API/scripts/data_controller_processor")
                with lock:
                    sk = Path(f'admins_private_keys/{role}_{admin_id}_new.pem')
                    sk.parent.mkdir(exist_ok=True, parents=True)
                    with open(f'admins_private_keys/{role}_{admin_id}_new.pem', "wb") as sk:
                        sk.write(new_private_key)
                log = Auth_HLF.update_public_key(admin_id, new_public_key.decode())
                if "status:200" in str(log):
                    log = log.decode("utf-8").split("->")[1]
                    return render(request, 'success.html',
                                  {'Action': "Change Admin Keys", 'Info': log, 'Private_Key': new_private_key.decode()})
                else:
                    return render(request, 'fail.html', {'Action': "Change Admin Keys", 'Info': log.decode()})
        else:
            return render(request, 'fail.html', {'Action': "Change Admin Keys", 'Info': "Form is not valid"})
    else:
        form = ControllerAdminPasswordForm()
    return render(request, 'forms.html', {'Title': 'Admin to update', 'form': form})



def controller_survey_list(request):
    if request.method == 'POST':
        action = "List Surveys"
        form = ListAllForm(request.POST, request.FILES)
        if form.is_valid():
            admin_id = form.cleaned_data['id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(admin_id))
            del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(admin_id, signature)
            if not sign_verification:
                return render(request, 'fail.html',
                              {'Action': action, 'Info': 'Wrong Controller Private Key'})
            role_response = Auth_HLF.getRole(admin_id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "controller":
                return render(request, 'fail.html',
                              {'Action': action, 'Info': 'Only Data Controller can perform this operation'})
            else:
                surveys = get_survey_list()
                for survey in surveys:
                    cids = survey['cids'].split(";")
                    cids.pop()
                    survey['cids'] = cids
                    survey['Fields'] = survey['Fields'].split(";")
                return render(request, 'controller/surveys/list.html', {'Action':action, 'Surveys': surveys},)
        else:
            return render(request, 'fail.html', {'Action': action, 'Info': "Form is not valid"})
    else:
        form = ListAllForm()
    return render(request, 'forms.html', {'Title': 'Authorization', 'form': form})



def controller_surveys_create(request):
    if request.method == 'POST':
        action = "Create Survey"
        form = CreateSurveyForm(request.POST, request.FILES)
        if form.is_valid():
            admin_id = form.cleaned_data['controller_id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(admin_id))
            del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(admin_id, signature)
            if not sign_verification:
                return render(request, 'fail.html',
                              {'Action': action, 'Info': 'Wrong Controller Private Key'})
            role_response = Auth_HLF.getRole(admin_id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "controller":
                return render(request, 'fail.html',
                              {'Action': action, 'Info': 'Only Data Controller can perform this operation'})
            else:
                survey_id = form.cleaned_data['survey_id']
                description = form.cleaned_data['description']
                fields = form.cleaned_data['fields']
                duration = form.cleaned_data['duration']
                deadline = datetime.now() + duration
                deadline= str(deadline.strftime("%Y-%m-%d %H:%M:%S"))
                log = Surveys_HLF.create(survey_id, description, fields, deadline)
                if "status:200" in str(log) :
                    log = log.decode("utf-8").split("->")[1]
                    return render(request, 'survey_success.html',
                                  {'Action': "Created Survey", 'Log2': log,})
                else:
                    return render(request, 'fail.html', {'Action': "Create User", 'Info': log.decode()})
        else:
            return render(request, 'fail.html', {'Action': action, 'Info': "Form is not valid"})
    else:
        form = CreateSurveyForm()
    return render(request, 'forms.html', {'Title': 'User To Delete', 'form': form})




def controller_surveys_delete(request):
    if request.method == 'POST':
        action = "Delete Survey"
        form = DeleteSurvey(request.POST, request.FILES)
        if form.is_valid():
            survey_id = form.cleaned_data['survey_id']
            admin_id = form.cleaned_data['id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(admin_id))
            del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(admin_id, signature)
            if not sign_verification:
                return render(request, 'fail.html',
                              {'Action': action, 'Info': 'Wrong Controller Private Key'})
            role_response = Auth_HLF.getRole(admin_id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "controller":
                return render(request, 'fail.html',
                              {'Action': action, 'Info': 'Only Data Controller can perform this operation'})
            else:
                survey = get_survey(survey_id)
                if len(survey) == 0:
                    return render(request, 'fail.html',
                                  {'Action': action , 'Info': 'Survey do not exist'})
                else:
                    cids = survey['cids'].split(";")
                    cids.pop()
                    result = True
                    not_deleted = []
                    for cid in cids:
                        # the result turns false if one of the files is not removed from ipfs
                        current_result = IPFS.delete(cid)
                        result = result and current_result
                        if not current_result:
                            not_deleted.append(cid)
                    if not result:
                        return render(request, 'fail.html', {'Action': action + "could not delete this files:", 'Info': not_deleted})
                    else:
                        log = Surveys_HLF.delete(survey_id)
                        if "status:200" in str(log):
                            log = log.decode("utf-8").split("->")[1]
                            return render(request, 'survey_success.html',
                                          {'Action': action, 'Log1': log,})
                        else:
                            return render(request, 'fail.html', {'Action': action, 'Info': log.decode()})
        else:
            return render(request, 'fail.html', {'Action': action, 'Info': "Form is not valid"})
    else:
        form = DeleteSurvey()
    return render(request, 'forms.html', {'Title': 'Survey To Delete', 'form': form})

def controller_add_update_participation(request, survey_id):
    action = "Add Participation to Survey"
    surveys_ids = [survey['ID'] for survey in get_survey_list()]
    if survey_id not in surveys_ids:
        return render(request, 'fail.html', {'Action': "Participate in Survey", 'Info': "The survey " + survey_id + " does not exists"})
    else:
        survey = get_survey(survey_id)
        fields = survey['Fields']
        fields = fields.split(";")
        if request.method == 'POST':
            form = ControllerSurveyForm(fields, request.POST, request.FILES)
            if form.is_valid():
                admin_id = form.cleaned_data['admin_id']
                user_id = form.cleaned_data['user_id']
                #authentication
                private_key_bytes = request.FILES['file'].read()
                signature = RSA.sign(private_key_bytes, str(admin_id))
                del private_key_bytes
                sign_verification = Auth_HLF.verify_signature(admin_id, signature)
                if not sign_verification:
                    return render(request, 'fail.html',
                                  {'Action': action, 'Info': 'Wrong Controller Private Key'})
                role_response = Auth_HLF.getRole(admin_id)
                aux = re.search('payload:"(.*)"', role_response.decode())
                role = aux.group(1)
                if role != "controller":
                    return render(request, 'fail.html',
                                  {'Action': action, 'Info': 'Only Data Controller can perform this operation'})
                else:
                    del form.cleaned_data['user_id']
                    del form.cleaned_data['admin_id']
                    del form.cleaned_data['file']
                    cid, ipfs_hash = IPFS.write_survey(form.cleaned_data)
                    asset = HLF.read(user_id).decode("utf-8")
                    if "status:200" in str(asset):
                        asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                        asset = "{" + asset + "}"
                        asset_dict = json.loads(asset)
                    if survey_id in asset_dict['surveys']:
                        survey_cid = (asset_dict['surveys'].split(survey_id+"_"))[1].split(';')[0]
                        IPFS.delete(survey_cid)
                        HLF.delete_cid_from_survey(user_id, survey_id, survey_cid )
                        Surveys_HLF.remove_cid(survey_id,survey_cid)

                    log_hlf = HLF.add_cid_to_survey(user_id, survey_id,cid)
                    log_surveys = Surveys_HLF.add_cid(survey_id, cid)
                    log_hlf = log_hlf.decode("utf-8").split("->")[1]
                    log_surveys = log_surveys.decode("utf-8").split("->")[1]
                    return render(request, 'survey_success.html',
                                  {'Action': "Answer Survey",
                                   'Log1':  log_hlf, 'Log2':  log_surveys,
                                   "CID": cid})
            else:
                return render(request, 'fail.html', {'Action': "Participate in the survey", 'Info': "Form is not valid", 'form':form})
        else:
            form = ControllerSurveyForm(poll=fields)
    return render(request, 'survey_form.html', {'Title': 'Survey Participation', 'form': form, 'Survey':survey })

def controller_surveys_remove_participation(request):
    if request.method == 'POST':
        action = "Delete Participation from Survey"
        form = ControllerRemoveParticipation(request.POST, request.FILES)
        if form.is_valid():
            admin_id = form.cleaned_data['admin_id']
            user_id = form.cleaned_data['user_id']
            private_key_bytes = request.FILES['file'].read()
            signature = RSA.sign(private_key_bytes, str(admin_id))
            del private_key_bytes
            sign_verification = Auth_HLF.verify_signature(admin_id, signature)
            if not sign_verification:
                return render(request, 'fail.html',
                              {'Action': action, 'Info': 'Wrong Controller Private Key'})
            role_response = Auth_HLF.getRole(admin_id)
            aux = re.search('payload:"(.*)"', role_response.decode())
            role = aux.group(1)
            if role != "controller":
                return render(request, 'fail.html',
                              {'Action': action, 'Info': 'Only Data Controller can perform this operation'})
            else:
                asset = HLF.read(user_id).decode("utf-8")
                survey_id = form.cleaned_data['survey_id']
                if "status:200" in str(asset):
                    asset = (asset.split('"{'))[1].split('}"')[0].replace("\\", "")
                    asset = "{" + asset + "}"
                    asset_dict = json.loads(asset)

                    surveys = get_user_participation(asset_dict)
                    if survey_id not in surveys.keys():
                        return render(request, 'success.html',
                                      {'Info': 'The user has not participated in this survey, yet.'}, )

                    survey_cid = (asset_dict['surveys'].split(survey_id + "_"))[1].split(';')[0]
                    result = IPFS.delete(survey_cid)
                    log_hlf = HLF.delete_cid_from_survey(user_id, survey_id, survey_cid)
                    log_surveys = Surveys_HLF.remove_cid(survey_id, survey_cid)
                    log_hlf = log_hlf.decode("utf-8")
                    log_surveys = log_surveys.decode("utf-8")
                    if result and "status:200" in str(log_hlf) and "status:200" in str(log_surveys):
                        log_hlf = log_hlf.split("->")[1]
                        log_surveys = log_surveys.split("->")[1]
                        return render(request, 'survey_success.html',
                                      {'Action': "Answer Survey",
                                       'Log1': log_hlf, 'Log2': log_surveys})
                    else:
                        return render(request, 'fail.html',
                                              {'Action': "Delete Survey", 'Info': 'Could not delete the ipfs file'}, )

        else:
            return render(request, 'fail.html', {'Action': action, 'Info': "Form is not valid"})
    else:
        form = ControllerRemoveParticipation()
    return render(request, 'forms.html', {'Title': 'User To Delete', 'form': form})




def delete_survey(survey_id):
    survey = get_survey(survey_id)
    cids = survey['cids'].split(";")
    cids.pop()
    for cid in cids:
        IPFS.delete(cid)
    Surveys_HLF.delete(survey_id)


def observer():
    surveys = get_survey_list()
    for survey in surveys:
        deadline_str = survey['dealine']
        deadline = datetime.strptime(deadline_str, '%Y-%m-%d %H:%M:%S')
        now = datetime.now()
        #if deadline has passed, delete the survey
        if deadline < now:
            delete_survey(survey['ID'])
