groupObj = PairingGroup('SS512')
cpabe = CPabe_SP21(groupObj)
U = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN']
B = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE']
P = ['ONE', 'TWO', 'THREE']
(pk, mk) = cpabe.setup(10)
dk = cpabe.keygen(pk, mk, B)
print("dk :=>", dk)
rand_msg = groupObj.random(GT)
ct = cpabe.encrypt(pk, rand_msg, P)
print("\nCiphertext...\n", ct)
rec_msg = cpabe.decrypt(pk, dk, ct)
print("\nDecrypt...\n")
print("Rec msg =>", rec_msg)
print("\nRand msg =>", rand_msg)
if rand_msg==rec_msg:
    print("\nIt is correct")
else:
    print("\nIt is wrong")

