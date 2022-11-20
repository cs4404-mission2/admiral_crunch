class conversation:
    packets = []
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        self.enforce = False
