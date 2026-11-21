from lib import Repo

REPO = Repo(name="repo", default_branch="main", is_private=False, is_fork=False)
PRIVATE_REPO = Repo(name="repo", default_branch="main", is_private=True, is_fork=False)


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code
        self.is_success = status_code < 400

    def json(self):
        return {}


class _FakeResponseWithJson(_FakeResponse):
    def __init__(self, status_code, body):
        super().__init__(status_code)
        self._body = body

    def json(self):
        return self._body
