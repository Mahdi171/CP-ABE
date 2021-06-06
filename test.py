from CP_ABE import CPabe_SP21
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair

groupObj = PairingGroup('BN254')
cpabe = CPabe_SP21(groupObj)
U = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN']
B = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE']
P = ['ONE', 'TWO', 'THREE']
(pk, mk) = cpabe.setup(10)
dk = cpabe.keygen(pk, mk, B,U)
print("dk :=>", dk)
rand_msg = groupObj.random(GT)
ct = cpabe.encrypt(pk, rand_msg, P,U)
print("\nCiphertext...\n", ct)
rec_msg = cpabe.decrypt(pk, dk, ct)
print("\nDecrypt...\n")
print("Rec msg =>", rec_msg)
print("\nRand msg =>", rand_msg)
if rand_msg==rec_msg:
    print("\nIt is correct")
else:
    print("\nIt is wrong")

