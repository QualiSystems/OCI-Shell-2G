import requests

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RestClientException(Exception):
    pass


class RestClientUnauthorizedException(RestClientException):
    pass


class QualiAPIHelper(object):
    def __init__(self, server_name, username=None, password=None, token=None, domain=None, use_https=False):
        self._use_https = use_https
        self._session = requests.Session()
        self._server_name = server_name
        if ":" not in self._server_name:
            self._server_name += ":9000"
        self._domain = domain if domain else None
        self._username = username
        self._password = password
        self._token = token

    def login(self):
        """
        Login
        :return:
        """
        uri = 'API/Auth/Login'
        if self._token:
            json_data = {'token': self._token, 'domain': self._domain}
        else:
            json_data = {'username': self._username, 'password': self._password, 'domain': self._domain}
        response = self._session.put(self._build_url(uri), json_data, verify=False)
        result = self._valid(response).json()
        self._session.headers.update(authorization="Basic {0}".format(result.replace('"', '')))

    def attach_file_to_reservation(self, reservation_id, file_data, file_name):
        file_to_upload = {'QualiPackage': file_data}
        data = {
            "reservationId": reservation_id,
            "saveFileAs": file_name,
            "overwriteIfExists": "true",
        }

        uri = 'API/Package/AttachFileToReservation'
        response = self._session.post(self._build_url(uri), data=data, files=file_to_upload, verify=False)
        return self._valid(response).json()

    def _build_url(self, uri):
        if self._server_name not in uri:
            if not uri.startswith('/'):
                uri = '/' + uri
            if self._use_https:
                url = 'https://{0}{1}'.format(self._server_name, uri)
            else:
                url = 'http://{0}{1}'.format(self._server_name, uri)
        else:
            url = uri
        return url

    def _valid(self, response):
        if response.status_code in [200, 201, 204]:
            return response
        elif response.status_code in [401]:
            raise RestClientUnauthorizedException(self.__class__.__name__, 'Incorrect login or password')
        else:
            raise RestClientException(self.__class__.__name__,
                                      'Request failed: {0}, {1}'.format(response.status_code, response.text))

    def get_attached_files(self, reservation_id):
        uri = 'API/Package/GetReservationAttachmentsDetails/{0}'.format(reservation_id)
        response = self._session.get(self._build_url(uri), verify=False)
        result = self._valid(response).json()
        return result['AllAttachments']

    def remove_attached_files(self, reservation_id):
        uri = 'API/Package/DeleteFileFromReservation'
        for file_name in self.get_attached_files(reservation_id) or []:
            file_to_delete = {"reservationId": reservation_id,
                              "FileName": file_name
                              }
            response = self._session.post(self._build_url(uri), json=file_to_delete, verify=False)
            self._valid(response).json()
