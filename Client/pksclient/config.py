class Config:
    @staticmethod
    def get_interface_from_ip(ipadd) -> str:
        from netifaces import AF_INET
        import netifaces as ni
        for iface in ni.interfaces():
            try:
                for inet in ni.ifaddresses(iface)[AF_INET]:
                    if inet['addr'] == ipadd:
                        return iface
            except KeyError:
                pass
        raise Exception(f"Could not find a network interface with ip {ipadd}. Please verify IP address validity "
                        f"and/or enter the interface name manually.")
    
    server: str = "172.30.145.143"  # Linux server's IP address
    own_address: str = "192.168.194.54"  # Your Windows IP address
    interface: str = get_interface_from_ip(own_address)
    target_port: int = 22
