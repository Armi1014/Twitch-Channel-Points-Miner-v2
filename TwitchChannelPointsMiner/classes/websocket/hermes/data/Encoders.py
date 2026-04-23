import abc
import json


class RequestEncoder(abc.ABC):
    @abc.abstractmethod
    def encode(self, request) -> str:
        raise NotImplementedError()


class JsonEncoder(RequestEncoder):
    def encode(self, request) -> str:
        return json.dumps(request.to_dict(), separators=(",", ":"))
