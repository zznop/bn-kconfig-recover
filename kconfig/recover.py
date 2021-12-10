from binaryninja import BinaryView


class KConfigRecover:
    """Class that uses BN API to attempt to recover kernel configurations.
    """
    def __init__(self, bv: BinaryView):
        self.bv = bv
