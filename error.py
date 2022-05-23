from http import HTTPStatus
import re

class BaseError():
	def __init__(self, code, error, errorMessage, cause=None):
		self.code = code
		self.error = error
		self.errorMessage = errorMessage
		self.cause = cause
	def serialize(self):
		if self.cause == None:
			return {"error": self.error, "errorMessage": self.errorMessage}
		else:
			return {"error": self.error, "errorMessage": self.errorMessage, "cause": self.cause}

class InvalidToken(BaseError):
    def __init__(self, cause=None):
        self.code = 403
        self.error = "ForbiddenOperationException"
        self.errorMessage = "Invalid token."
        self.cause = cause
        
class InvalidCredentials(BaseError):
    def __init__(self, cause=None):
        self.code = 403
        self.error = "ForbiddenOperationException"
        self.errorMessage = "Invalid credentials. Invalid username or password."
        self.cause = cause
        
class TokenAssigned(BaseError):
    def __init__(self, cause=None):
        self.code = 400
        self.error = "IllegalArgumentException"
        self.errorMessage = "Access token already has a profile assigned."
        self.cause = cause
        
class TokenAssignForbidden(BaseError):
    def __init__(self, cause=None):
        self.code = 403
        self.error = "ForbiddenOperationException"
        self.errorMessage = "Character Non-belonging"
        self.cause = cause
        
class InvalidPlayer(BaseError):
    def __init__(self, cause=None):
        self.code = 403
        self.error = "ForbiddenOperationException"
        self.errorMessage = "Invalid token."
        self.cause = cause
        
class HTTPError(BaseError):
    def __init__(self, code, cause=None):
        dic = {}
        for x in HTTPStatus:
            dic[int(x)] = x
        self.code = int(re.sub("[^0-9]", "", str(code)))
        self.error = dic[int(re.sub("[^0-9]", "", str(code)))].phrase
        self.errorMessage = dic[int(re.sub("[^0-9]", "", str(code)))].description
        self.cause = cause
        
class HTTP204(BaseError):
    def __init__(self):
        self.code = 204
        self.error = ""
        self.errorMessage = ""
        self.cause = ""
    def serialize(self):
        return ""