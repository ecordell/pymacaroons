
class BaseBinder(object):
    def __init__(self, root):
        self.root = root

    def bind(self, discharge):
        protected = discharge.copy()
        protected._signature = self.bind_signature(discharge._signature)
        return protected

    def bind_signature(self, signature):
        raise NotImplementedError()
