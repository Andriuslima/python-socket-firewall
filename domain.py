class PacketFlow:
    id: str
    src: str
    dst: str
    protocol: str
    port_src: str
    port_dst: str
    enabled: bool

    def __init__(self, src, dst, protocol, port_src=None, port_dst=None):
        id_infos = filter(None, [src, dst, protocol, port_src, port_dst])
        self.id = "_".join(id_infos)
        self.src = src
        self.dst = dst
        self.protocol = protocol
        self.port_src = port_src
        self.port_dst = port_dst
        self.enabled = True

    def __str__(self):
        enabled_str = "[On]" if self.enabled else "[Off]"
        return f"Source: {self.src} -> {self.dst} with {self.protocol} protocol " \
               f"| Source Port: {self.port_src}, Destination Port: {self.port_dst} | {enabled_str}"

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.id == other.id
