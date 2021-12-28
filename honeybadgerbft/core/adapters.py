from dssim.components.queue import Queue as DSQueue
from dssim.components.event import Event as DSEvent
from dssim.simulation import DSSchedulable
import sys

class Queue(DSQueue):
    class Full(Exception):
        pass

    def __init__(self, maxsize=0, *args, **kwargs):
        self.maxsize = maxsize or sys.maxsize
        super().__init__(*args, **kwargs)

    def put_nowait(self, obj):
        if len(self) < self.maxsize:
            super().put(data=obj)
        else:
            raise Queue.Full()

    @DSSchedulable
    def put(self, obj):
        if len(self) < self.maxsize:
            super().put(data=obj)
        else:
            raise Queue.Full()

    def get(self):
        d = yield from super().get()
        return d['data']

    def get_nowait(self):
        try:
            rv = next(self.get())
        except StopIteration as e:
            rv = e.value
        return rv

class Event(DSEvent):
    def set(self):
        super().signal()
