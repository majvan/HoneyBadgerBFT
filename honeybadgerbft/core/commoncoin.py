import logging

from dssim.simulation import sim, DSSchedulable
from honeybadgerbft.core.adapters import Queue

from honeybadgerbft.crypto.threshsig.boldyreva import serialize
from collections import defaultdict
#from gevent import Greenlet
#from gevent.queue import Queue
import hashlib

logger = logging.getLogger(__name__)


class CommonCoinFailureException(Exception):
    """Raised for common coin failures."""
    pass


def hash(x):
    return hashlib.sha256(x).digest()


def shared_coin(sid, pid, N, f, PK, SK, broadcast, receive):
    """A shared coin based on threshold signatures

    :param sid: a unique instance id
    :param pid: my id number
    :param N: number of parties
    :param f: fault tolerance, :math:`f+1` shares needed to get the coin
    :param PK: ``boldyreva.TBLSPublicKey``
    :param SK: ``boldyreva.TBLSPrivateKey``
    :param broadcast: broadcast channel
    :param receive: receive channel
    :return: a function ``getCoin()``, where ``getCoin(r)`` blocks
    """
    assert PK.k == f+1
    assert PK.l == N    # noqa: E741
    received = defaultdict(dict)
    outputQueue = defaultdict(lambda: Queue(1))

    @DSSchedulable
    def _recv():
        while True:     # main receive loop
            logger.debug(f'entering loop ' +
                         f'nodeid: {pid}, epoch: ?'
                         )
            # New shares for some round r, from sender i
            (i, (_, r, sig)) = yield from receive()
            logger.debug(f'received i, _, r, sig: {i, _, r, sig} ' +
                         f'nodeid: {pid}, epoch: {r}'
                         )
            assert i in range(N)
            assert r >= 0
            if i in received[r]:
                logger.debug(f"redundant coin sig received")
                continue

            h = PK.hash_message(str((sid, r)))

            # TODO: Accountability: Optimistically skip verifying
            # each share, knowing evidence available later
            try:
                PK.verify_share(sig, i, h)
            except AssertionError:
                logger.debug("signature share failed!")
                continue

            received[r][i] = sig

            # After reaching the threshold, compute the output and
            # make it available locally
            logger.debug(
                f'received {len(received[r])} messages in round {r}, f + 1 = {f + 1} needed. ' +
                f'nodeid: {pid}, epoch: {r}'
            )
            if len(received[r]) == f + 1:

                # Verify and get the combined signature
                sigs = dict(list(received[r].items())[:f+1])
                sig = PK.combine_shares(sigs)
                assert PK.verify_signature(sig, h)

                # Compute the bit from the least bit of the hash
                bit = hash(serialize(sig))[0] % 2
                logger.debug(f'put bit {bit} in output queue ' +
                             f'nodeid: {pid}, epoch: {r}'
                             )
                outputQueue[r].put_nowait(bit)

    sim.schedule(0, _recv())

    def getCoin(round):
        """Gets a coin.

        :param round: the epoch/round.
        :returns: a coin.

        """
        # I have to do mapping to 1..l
        h = PK.hash_message(str((sid, round)))
        logger.debug(f"broadcast(o={('COIN', round, SK.sign(h))}) " +
                     f'nodeid: {pid}, epoch: {round}'
                     )
        broadcast(('COIN', round, SK.sign(h)))
        obj = yield from outputQueue[round].get()
        return obj

    return getCoin
