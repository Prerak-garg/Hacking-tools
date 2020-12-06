import  netfilterqueue

def process_packet(packet):
    print(packet)
    packet.drop()

queue = netfilterqueue.Netfilter()
queue.bind(0, process_packet)
queue.run()
