import random

def generate_bits(n):
    return [random.randint(0,1) for _ in range(n)]

def generate_bases(n):
    return [random.choice(['Z','X']) for _ in range(n)]

def encode_qubits(bits, bases):
    return list(zip(bits,bases))

def measure_qubits(qubits, receiver_bases):

    measured_bits = []

    for (bit, basis), r_basis in zip(qubits, receiver_bases):

        if basis == r_basis:
            measured_bits.append(bit)
        else:
            measured_bits.append(random.randint(0,1))

    return measured_bits

def sift_key(sender_bases, receiver_bases, sender_bits, receiver_bits):

    key = []

    for sb, rb, bit in zip(sender_bases, receiver_bases, receiver_bits):

        if sb == rb:
            key.append(bit)

    return key

def bb84_protocol(n=32):

    sender_bits = generate_bits(n)
    sender_bases = generate_bases(n)

    qubits = encode_qubits(sender_bits, sender_bases)

    receiver_bases = generate_bases(n)

    receiver_bits = measure_qubits(qubits, receiver_bases)

    shared_key = sift_key(sender_bases, receiver_bases, sender_bits, receiver_bits)

    key_string = ''.join(map(str,shared_key))

    return key_string