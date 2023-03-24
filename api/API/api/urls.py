"""api URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path, re_path
from api.bc_ipfs import views


urlpatterns = [
    path('', views.root),
    path('user/', views.user),
    path('processor/', views.processor),
    path('controller/', views.controller),

    path('user/create/', views.create),
    path('user/read/',   views.read),
    path('user/update/', views.update),
    path('user/delete/', views.delete),
    path('user/surveys/', views.surveys),
    path('user/surveys/listall/', views.surveys),

    path('user/surveys/participate/', views.survey_list),
    path('user/surveys/participate/<str:survey_id>/', views.survey_create_update, name='survey_id'),
    path('user/surveys/read/', views.survey_read),
    path('user/surveys/delete/', views.survey_delete),
    path('user/passwd/', views.change_password),

    path('processor/listall/', views.listall),
    path('processor/listall_survey/', views.listall_survey),
    path('processor/listall_field/', views.listall_field),
    path('processor/read/', views.admin_read),

    path('controller/create/', views.create),
    path('controller/read/', views.admin_read),
    path('controller/update/', views.controller_update),
    path('controller/delete/', views.controller_delete),
    path('controller/listall/', views.listall),
    path('controller/user_passwd/', views.controller_user_passwd),
    path('controller/passwd/', views.controller_passwd),

    path('controller/surveys/', views.controller_surveys_page),
    path('controller/surveys/list', views.controller_survey_list),
    path('controller/surveys/create/', views.controller_surveys_create),
    path('controller/surveys/delete/', views.controller_surveys_delete),
    path('controller/surveys/add_participation/', views.add_participation_survey_list),
    path('controller/surveys/add_participation/<str:survey_id>/', views.controller_add_update_participation, name='survey_id'),
    path('controller/surveys/remove_participation', views.controller_surveys_remove_participation),



]


