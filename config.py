import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
     
    SECRET_KEY = 'GIVE VALUE HERE'
    DEBUG = True
    UPLOAD_FOLDER = 'uploads'
    DEFAULT_FOLDER = 'static/default'

    #-------oauth settings---------#
    OAUTH_CLIENT = 'google'

    GOOGLE_CLIENT_ID = '1051524488482-9p4r4sbo0vcs5b2k2kdsh377o6p0e1sd.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = 'lDQimvLLD4FkDAExqDKetm5v'
    REDIRECT_URI = '/oauth2callback'  # one of the Redirect URIs from Google APIs console

    BASE_URL='https://www.google.com/accounts/'
    AUTHORIZE_URL='https://accounts.google.com/o/oauth2/auth'
    REQUEST_TOKEN_URL=None
    REQUEST_TOKEN_PARAMS={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                        'response_type': 'code'}
    ACCESS_TOKEN_URL='https://accounts.google.com/o/oauth2/token'
    ACCESS_TOKEN_METHOD='POST'
    ACCESS_TOKEN_PARAMS={'grant_type': 'authorization_code'}
    #-------oauth settings---------#

class ProductionConfig(Config):
    DEBUG = False


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
