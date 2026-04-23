import abc

from TwitchChannelPointsMiner.classes.entities.PubsubTopic import PubsubTopic


class WebSocketPool(abc.ABC):
    @abc.abstractmethod
    def start(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def end(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def submit(self, topic: PubsubTopic):
        raise NotImplementedError()

    @abc.abstractmethod
    def check_stale_connections(self):
        raise NotImplementedError()
