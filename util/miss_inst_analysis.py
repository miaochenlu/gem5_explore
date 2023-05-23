import os
import protolib
import subprocess
import sys
import matplotlib.pyplot as plt

util_dir = os.path.dirname(os.path.realpath(__file__))
# Make sure the proto definitions are up to date.
subprocess.check_call(["make", "--quiet", "-C", util_dir, "packet_pb2.py"])
import packet_pb2

miss_count = {}


def main():
    if len(sys.argv) != 3:
        print("Usage: ", sys.argv[0], " <protobuf input> <ASCII output>")
        exit(-1)

    # Open the file in read mode
    proto_in = protolib.openFileRd(sys.argv[1])

    try:
        ascii_out = open(sys.argv[2], "w")
    except IOError:
        print("Failed to open ", sys.argv[2], " for writing")
        exit(-1)

    # Read the magic number in 4-byte Little Endian
    magic_number = proto_in.read(4).decode()

    if magic_number != "gem5":
        print("Unrecognized file", sys.argv[1])
        exit(-1)

    print("Parsing packet header")

    # Add the packet header
    header = packet_pb2.PacketHeader()
    protolib.decodeMessage(proto_in, header)

    print("Object id:", header.obj_id)
    print("Tick frequency:", header.tick_freq)

    for id_string in header.id_strings:
        print("Master id %d: %s" % (id_string.key, id_string.value))

    print("Parsing packets")

    num_packets = 0
    packet = packet_pb2.Packet()

    # Decode the packet messages until we hit the end of the file
    no_pc_counter = 0
    has_pc_counter = 0
    while protolib.decodeMessage(proto_in, packet):
        num_packets += 1

        if packet.HasField("pc") and packet.cmd == 1:
            # print('pc 0x%x' % (packet.pc))
            if packet.pc in miss_count:
                miss_count[packet.pc] += 1
            else:
                miss_count[packet.pc] = 1
            has_pc_counter = has_pc_counter + 1
        else:
            no_pc_counter += 1
    print("no pc: ", no_pc_counter)
    print("has pc: ", has_pc_counter)
    print("Parsed packets:", num_packets)
    sorted_by_pc = sorted(miss_count.items(), key=lambda x: x[1])
    sorted_miss = dict(sorted_by_pc)
    # We're done
    ascii_out.close()
    proto_in.close()

    miss_count_tmp = dict(
        (k, v) for (k, v) in sorted_miss.items() if v > 60000
    )
    miss_key_tmp = list(miss_count_tmp.keys())
    miss_key = list(map(lambda x: hex(x).split("x")[1].zfill(5), miss_key_tmp))
    x = []
    for i in range(len(miss_key)):
        x.append(i)
    miss_val = list(miss_count_tmp.values())
    print(miss_key)
    print(miss_val)

    # fig, ax = plt.subplots()
    # plt.rcParams["font.family"] = "Times New Roman"
    plt.rcParams["font.size"] = 8
    bars = plt.bar(x, miss_val)
    # plt.bar_label(bars)
    plt.ylim(-10, 400000)
    plt.xticks(x, miss_key, rotation=90)
    plt.xlabel("PC")
    plt.ylabel("Count")
    plt.title("CPU->L1d Load Inst PC")
    # plt.xlabel(miss_key)
    # plt.show()
    plt.savefig("icx_cpu_l1d.png", dpi=1000, bbox_inches="tight")


if __name__ == "__main__":
    main()
