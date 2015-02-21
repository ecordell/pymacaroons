class BaseSerializer(object):

    def serialize(self, macaroon):
        raise NotImplementedError()

    def deserialize(self, serialized):
        raise NotImplementedError()
