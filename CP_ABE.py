from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from collections import defaultdict
from Zeropoly import Zero_poly

# type annotations'
pk_t = { 'g_2':G1, 'h_i':G2, 'e_gg_alpha':GT}
mk_t = {'alpha':ZR, 'g':G1 }
sk_t = { 'dk':G1, 'B':str }
ct_t = { 'C':GT, 'C1':G1, 'C2':G2, 'policy':str }

debug = False
class CPabe_SP21(ABEnc):
         
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj
    
    @Output(pk_t, mk_t)    
    def setup(self,uni_size):
        g, h, alpha = group.random(G1), group.random(G2), group.random(ZR)
        g.initPP(); h.initPP()
        g_2 = g ** (alpha**2)
        e_gg_alpha = pair(g,h)**alpha
        h_i= {}
        for j in range(uni_size+1):
            h_i[j] = h ** (alpha ** j)
        pk = {'g_2':g_2, 'h_i':h_i, 'e_gg_alpha':e_gg_alpha}
        mk = {'alpha':alpha, 'g':g }
        return (pk, mk)

    
    @Input(pk_t, mk_t, [str],[str])
    @Output(sk_t)
    def keygen(self, pk, mk, B,U):
        S= list(set(U) - set(B)); Zerop=1
        for attrs in S:
            Zerop *= mk['alpha'] + group.hash(attrs, ZR) 
        dk = mk['g'] ** (1/Zerop)
        return { 'dk':dk, 'B':B }
    
    @Input(pk_t, GT, [str])
    @Output(ct_t)
    def encrypt(self, pk, M, P,U): 
        a=[]; C2=1
        Com_set= list(set(U) - set(P))
        for attrs in Com_set:
            a.append(group.hash(attrs, ZR))
        (indices,coeff_mult)=Zero_poly(a,len(a)-1,[0],[1])
        Coeffs=list(reversed(coeff_mult))
        for i in range(len(indices)):
            C2*= (pk['h_i'][i+1] ** Coeffs[i])
        r = group.random(ZR)     
        C = M * (pk['e_gg_alpha'] ** r)
        C1 = pk['g_2'] ** (-r)
        C2 = C2 ** r
        return { 'C':C ,'C1':C1, 'C2':C2, 'policy':P}
    
    @Input(pk_t, sk_t, ct_t)
    @Output(GT)
    def decrypt(self, pk, sk, ct):
        A=list(set(sk['B'])-set(ct['policy']))
        a=[]; z=1
        for attrs in A:
            a.append(group.hash(attrs, ZR))
        (indices,coeff_mult)=Zero_poly(a,len(a)-1,[0],[1])
        Coeffs=list(reversed(coeff_mult))
        for i in range(len(indices)-1):
            z*= pk['h_i'][i] ** Coeffs[i+1]
        V=(pair(ct['C1'],z) * pair(sk['dk'],ct['C2']))
        return ct['C'] * (V**(-1/Coeffs[0]))
